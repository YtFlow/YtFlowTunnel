using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Wintun2socks;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal class TunSocketAdapter : ILocalAdapter
    {
        private readonly TcpSocket _socket;
        private readonly TunInterface _tun;
        private readonly PipeReader inboundReader;
        private readonly PipeWriter inboundWriter;
        private readonly IRemoteAdapter remoteAdapter;
        private CancellationTokenSource pushCancelSource = new CancellationTokenSource();
        private readonly CancellationTokenSource recvCancel = new CancellationTokenSource();
        private readonly CancellationTokenSource sendCancel = new CancellationTokenSource();
        private SemaphoreSlim localStackBufLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim localWriteFinishLock = new SemaphoreSlim(0, 1);
        private readonly Channel<byte[]> outboundChan = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(4)
        {
            SingleReader = true
        });
        private int localStackAvailableByteCount = 11680;
        private int localPendingByteCount = 0;
        public int IsShutdown = 0;
        public Destination.Destination Destination { get; set; }

        public static int OpenCount = 0;
        public static int RecvingCount = 0;
        public static int SendingCount = 0;

        internal TunSocketAdapter (TcpSocket socket, TunInterface tun, IRemoteAdapter remoteAdapter)
        {
            Interlocked.Increment(ref OpenCount);
            var pipe = new Pipe();
            inboundReader = pipe.Reader;
            inboundWriter = pipe.Writer;
            _socket = socket;
            _tun = tun;

            socket.DataReceived += Socket_DataReceived;
            socket.DataSent += Socket_DataSent;
            socket.SocketError += Socket_SocketError;
            socket.RecvFinished += Socket_RecvFinished;

            // Resolve destination host
            var host = DnsProxyServer.TryLookup(socket.RemoteAddr);
            Destination = new Destination.Destination(host, socket.RemotePort, TransportProtocol.Tcp);

            StartPush();
            this.remoteAdapter = remoteAdapter;
            Init();
        }
        private async void Init ()
        {
            try
            {
                await remoteAdapter.Init(outboundChan.Reader, this);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"Error initiating a connection to {Destination}: {ex}");
                remoteAdapter.RemoteDisconnected = true;
                Reset();
                CheckShutdown();
                return;
            }
            if (DebugLogger.LogNeeded())
            {
                DebugLogger.Log("Connected: " + Destination.ToString());
            }
            await StartForward().ConfigureAwait(false);
        }

        private unsafe ValueTask<byte> SendToSocket (MemoryHandle dataHandle, ushort len, bool more)
        {
            return _tun.executeLwipTask(() => _socket.Send((ulong)dataHandle.Pointer, len, more));
        }

        private async ValueTask<bool> PushOne ()
        {
            var readResult = await inboundReader.ReadAsync(pushCancelSource.Token).ConfigureAwait(false);
            var buffer = readResult.Buffer;
            byte writeResult = 0;
            var start = buffer.Start;
            // A buffer may consist of several Memory<byte> chunks,
            // read one of them at a time.
            // Note that a chunk may be large, thus must be splitted into smaller chunks.
            while (buffer.TryGet(ref start, out var remainingChunk))
            {
                while (remainingChunk.Length > 0)
                {
                    // Wait until there is enough space in the stack
                    while (localStackAvailableByteCount <= 1600)
                    {
                        await localStackBufLock.WaitAsync(pushCancelSource.Token).ConfigureAwait(false);
                    }
                    var len = Math.Min(localStackAvailableByteCount, remainingChunk.Length);
                    var chunk = remainingChunk.Slice(0, len);
                    remainingChunk = remainingChunk.Slice(len);
                    var more = remainingChunk.Length != 0 || !start.Equals(buffer.End);
                    using (var dataHandle = chunk.Pin())
                    {
                        writeResult = await SendToSocket(dataHandle, (ushort)chunk.Length, more).ConfigureAwait(false);
                        while (writeResult == 255)
                        {
                            if (!await (localStackBufLock?.WaitAsync(10000, pushCancelSource.Token).ConfigureAwait(false) ?? Task.FromResult(false).ConfigureAwait(false)))
                            {
                                DebugLogger.Log("Local write timeout");
                                break;
                            }
                            writeResult = await SendToSocket(dataHandle, (ushort)chunk.Length, more).ConfigureAwait(false);
                        }
                    }
                    if (writeResult != 0)
                    {
                        DebugLogger.Log("Error from writing to local socket:" + writeResult.ToString());
                        // TODO: distinguish write error with general socket error
                        Socket_SocketError(_socket, writeResult);
                        return false;
                    }
                    Interlocked.Add(ref localStackAvailableByteCount, -chunk.Length);
                    Interlocked.Add(ref localPendingByteCount, chunk.Length);
                    await _tun.executeLwipTask(() => _socket.Output());
                }
            }
            inboundReader.AdvanceTo(buffer.End);
            await _tun.executeLwipTask(() => _socket.Output());

            if (readResult.IsCanceled || readResult.IsCompleted || writeResult != 0 || pushCancelSource.IsCancellationRequested)
            {
                return false;
            }
            return true;
        }

        private async void StartPush ()
        {
            localStackAvailableByteCount = await _tun.executeLwipTask(() => _socket.SendBufferSize);
            try
            {
                while (await PushOne().ConfigureAwait(false)) { }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                DebugLogger.Log("Push error: " + ex.ToString());
            }
            finally
            {
                Interlocked.Exchange(ref pushCancelSource, null).Dispose();
            }
            // In case no data is written to local, close the socket.
            if (localPendingByteCount == 0 && localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        private async ValueTask<bool> PollOneFromRemote (CancellationToken cancellationToken = default)
        {
            var size = await remoteAdapter.GetRecvBufSizeHint(4096, cancellationToken).ConfigureAwait(false);
            if (size == 0)
            {
                return false;
            }
            var bufMemory = inboundWriter.GetMemory(size);
            if (!MemoryMarshal.TryGetArray<byte>(bufMemory, out var bufSegment))
            {
                throw new InvalidOperationException("Cannot get buffer segment from memory");
            }
            size = await remoteAdapter.StartRecv(bufSegment, cancellationToken).ConfigureAwait(false);
            if (size == 0)
            {
                return false;
            }
            inboundWriter.Advance(size);
            await inboundWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }

        private async ValueTask StartRecvFromRemote ()
        {
            try
            {
                while (await PollOneFromRemote(recvCancel.Token).ConfigureAwait(false)) { }
                if (recvCancel.IsCancellationRequested)
                {
                    return;
                }
                await FinishInbound().ConfigureAwait(false);
                if (DebugLogger.LogNeeded())
                {
                    DebugLogger.Log("Close!: " + Destination);
                }
                await Close().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                inboundWriter.Complete(ex);
                if (!(ex is OperationCanceledException))
                {
                    DebugLogger.Log($"Recv error: {Destination}: {ex}");
                    throw;
                }
            }
            finally
            {
                Interlocked.Decrement(ref RecvingCount);
                sendCancel.Cancel();
            }
        }

        private async ValueTask StartSendToRemote ()
        {
            try
            {
                await remoteAdapter.StartSend(outboundChan, sendCancel.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                recvCancel.Cancel();
            }
            catch (Exception ex)
            {
                recvCancel.Cancel();
                // Write a log if the exception is not lwIP Reset
                if (!(ex is LwipException lwipEx) || lwipEx.LwipCode != -14)
                {
                    DebugLogger.Log($"Send error: {Destination}: {ex}");
                }
                throw;
            }
            finally
            {
                Interlocked.Decrement(ref SendingCount);
            }
        }

        public async ValueTask StartForward ()
        {
            try
            {
                Interlocked.Increment(ref RecvingCount);
                Interlocked.Increment(ref SendingCount);
                var sendTask = StartSendToRemote().ConfigureAwait(false);
                var recvTask = StartRecvFromRemote().ConfigureAwait(false);
                // TODO: send first or recv?
                await sendTask;
                await recvTask;
            }
            catch (Exception)
            {
                // Something wrong happened during recv/send and was handled separatedly.
                DebugLogger.Log("Reset!: " + Destination);
                Reset();
            }
            finally
            {
                recvCancel.Cancel();
                sendCancel.Cancel();
            }
            remoteAdapter.RemoteDisconnected = true;
            CheckShutdown();
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public async ValueTask FlushInboundWriter (CancellationToken cancellationToken)
        {
            await inboundWriter.FlushAsync(cancellationToken);
        }

        public ValueTask WritePacketToLocal (Span<byte> data, CancellationToken cancellationToken = default)
        {
            data.CopyTo(inboundWriter.GetSpan(data.Length));
            inboundWriter.Advance(data.Length);
            return FlushInboundWriter(cancellationToken);
        }

        private async void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            DebugLogger.Log("Socket error " + err.ToString());
            if (!remoteAdapter.RemoteDisconnected)
            {
                try
                {
                    sendCancel.Cancel();
                }
                catch (ObjectDisposedException) { }
                try
                {
                    recvCancel.Cancel();
                }
                catch (ObjectDisposedException) { }
                try
                {
                    await outboundChan.Writer.WaitToWriteAsync();
                }
                catch (Exception)
                {
                    // The exception has been propagated to the remote adapter
                }
                outboundChan.Writer.TryComplete(new LwipException(err));
            }
            if (localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        private void Socket_DataSent (TcpSocket sender, ushort length, ushort buflen)
        {
            // Interlocked.Add(ref localStackByteCount, length);
            localStackAvailableByteCount = buflen;
            Interlocked.Add(ref localPendingByteCount, -length);
            if (localStackBufLock.CurrentCount == 0)
            {
                try
                {
                    localStackBufLock.Release();
                }
                catch (SemaphoreFullException) { }
            }
            if (pushCancelSource == null && localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        private async void Socket_DataReceived (TcpSocket sender, byte[] bytes)
        {
            try
            {
                await outboundChan.Writer.WriteAsync(bytes).ConfigureAwait(false);
                var len = (ushort)bytes.Length;
                _tun.executeLwipTask(() => _socket.Recved(len));
            }
            catch (Exception)
            {
                // TODO: ex?
            }
        }

        private async void Socket_RecvFinished (TcpSocket sender)
        {
            // Local FIN recved
            if (!remoteAdapter.RemoteDisconnected)
            {
                // Wait for pending writes to complete so that all data are
                // written into the channel buffer.
                await outboundChan.Writer.WaitToWriteAsync();
                outboundChan.Writer.TryComplete();
            }
        }

        public ValueTask<byte> Close ()
        {
            if (Interlocked.Exchange(ref IsShutdown, 1) == 1)
            {
                return new ValueTask<byte>(0);
            }
            pushCancelSource?.Cancel();
            return _tun.executeLwipTask(() => _socket.Shutdown());
        }

        public void Reset ()
        {
            if (Interlocked.Exchange(ref IsShutdown, 1) == 1)
            {
                return;
            }
            pushCancelSource?.Cancel();
            _tun.executeLwipTask(() => _socket.Abort());
        }

        public Task FinishInbound ()
        {
            inboundWriter.Complete();
            if (pushCancelSource != null || localPendingByteCount != 0)
            {
                return localWriteFinishLock.WaitAsync();
            }
            return Task.CompletedTask;
        }

        public virtual void CheckShutdown ()
        {
            Interlocked.Decrement(ref OpenCount);
            _socket.DataReceived -= Socket_DataReceived;
            _socket.DataSent -= Socket_DataSent;
            _socket.SocketError -= Socket_SocketError;
            _socket.RecvFinished -= Socket_RecvFinished;
            // TODO: return to array pool?
            // while (outboundChan.Reader.TryRead(out var buf))
            // {
            // }
            Interlocked.Exchange(ref localStackBufLock, null).Dispose();
            Interlocked.Exchange(ref localWriteFinishLock, null).Dispose();
            remoteAdapter.CheckShutdown();
            recvCancel.Dispose();
            sendCancel.Dispose();
        }
    }
}
