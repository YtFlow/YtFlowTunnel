using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;
using Wintun2socks;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal class TunSocketAdapter : ILocalAdapter
    {
        protected TcpSocket _socket;
        protected TunInterface _tun;
        protected PipeReader pipeReader;
        protected PipeWriter pipeWriter;
        private readonly IRemoteAdapter remoteAdapter;
        private CancellationTokenSource pollCancelSource = new CancellationTokenSource();
        private SemaphoreSlim localStackBufLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim localWriteFinishLock = new SemaphoreSlim(0, 1);
        private int localStackByteCount = 11680;
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
            pipeReader = pipe.Reader;
            pipeWriter = pipe.Writer;
            _socket = socket;
            _tun = tun;

            socket.DataReceived += Socket_DataReceived;
            socket.DataSent += Socket_DataSent;
            socket.SocketError += Socket_SocketError;
            socket.RecvFinished += Socket_RecvFinished;

            // Resolve destination host
            var domain = DnsProxyServer.Lookup(socket.RemoteAddr);
            IHost host;
            if (domain == null)
            {
                // TODO: Check if the remote addr falls in our IP range
                host = new Ipv4Host(socket.RemoteAddr);
            }
            else
            {
                host = new DomainNameHost(domain);
            }
            Destination = new Destination.Destination(host, socket.RemotePort, TransportProtocol.Tcp);

            StartPolling();
            this.remoteAdapter = remoteAdapter;
            remoteAdapter.Init(this).ContinueWith(async t =>
            {
                if (t.IsCanceled || t.IsFaulted)
                {
                    DebugLogger.Log($"Error initiating a connection to {Destination}: {t.Exception}");
                    remoteAdapter.RemoteDisconnected = true;
                    Reset();
                    CheckShutdown();
                }
                else
                {
                    if (DebugLogger.LogNeeded())
                    {
                        DebugLogger.Log("Connected: " + Destination.ToString());
                    }
                    await StartForward().ConfigureAwait(false);
                }
            });
        }

        private unsafe Task<byte> SendToSocket (MemoryHandle dataHandle, ushort len, bool more)
        {
#if X64
            return _tun.executeLwipTask(() => _socket.Send((long)dataHandle.Pointer, len, more));
#else
            return _tun.executeLwipTask(() => _socket.Send((int)dataHandle.Pointer, len, more));
#endif
        }

        private async Task<bool> PollOne ()
        {
            var readResult = await pipeReader.ReadAsync(pollCancelSource.Token).ConfigureAwait(false);
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
                    while (localStackByteCount <= 1600)
                    {
                        await localStackBufLock.WaitAsync(pollCancelSource.Token).ConfigureAwait(false);
                    }
                    var len = Math.Min(localStackByteCount, remainingChunk.Length);
                    var chunk = remainingChunk.Slice(0, len);
                    remainingChunk = remainingChunk.Slice(len);
                    var more = remainingChunk.Length != 0 || !start.Equals(buffer.End);
                    using (var dataHandle = chunk.Pin())
                    {
                        writeResult = await SendToSocket(dataHandle, (ushort)chunk.Length, more).ConfigureAwait(false);
                        while (writeResult == 255)
                        {
                            if (!await (localStackBufLock?.WaitAsync(10000, pollCancelSource.Token).ConfigureAwait(false) ?? Task.FromResult(false).ConfigureAwait(false)))
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
                    Interlocked.Add(ref localStackByteCount, -chunk.Length);
                    Interlocked.Add(ref localPendingByteCount, chunk.Length);
                    await _tun.executeLwipTask(() => _socket.Output());
                }
            }
            pipeReader.AdvanceTo(buffer.End);
            await _tun.executeLwipTask(() => _socket.Output());

            if (readResult.IsCanceled || readResult.IsCompleted || writeResult != 0 || pollCancelSource.IsCancellationRequested)
            {
                return false;
            }
            return true;
        }

        private async void StartPolling ()
        {
            localStackByteCount = await _tun.executeLwipTask(() => _socket.SendBufferSize);
            try
            {
                while (await PollOne().ConfigureAwait(false)) { }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                DebugLogger.Log("Poll error: " + ex.ToString());
            }
            finally
            {
                Interlocked.Exchange(ref pollCancelSource, null).Dispose();
            }
            // In case no data is written to local, close the socket.
            if (localPendingByteCount == 0 && localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        public async Task StartForward ()
        {
            var recvCancel = new CancellationTokenSource();
            var sendCancel = new CancellationTokenSource();
            try
            {
                Interlocked.Increment(ref RecvingCount);
                Interlocked.Increment(ref SendingCount);
                await Task.WhenAll(
                    remoteAdapter.StartRecv(recvCancel.Token).ContinueWith(async t =>
                   {
                       Interlocked.Decrement(ref RecvingCount);
                       sendCancel.Cancel();
                       if (t.IsFaulted)
                       {
                           var ex = t.Exception.Flatten().GetBaseException();
                           DebugLogger.Log($"Recv error: {Destination}: {ex}");
                       }
                       else if (t.Status == TaskStatus.RanToCompletion)
                       {
                           // Remote has closed the connection
                           await FinishInbound().ConfigureAwait(false);
                           if (DebugLogger.LogNeeded())
                           {
                               DebugLogger.Log("Close!: " + Destination);
                           }
                           await Close().ConfigureAwait(false);
                       }
                       return t;
                   }).Unwrap().Unwrap(),
                    remoteAdapter.StartSend(sendCancel.Token).ContinueWith(t =>
                   {
                       Interlocked.Decrement(ref SendingCount);
                       if (t.IsFaulted)
                       {
                           recvCancel.Cancel();
                           var ex = t.Exception.Flatten().GetBaseException();
                           if (!(ex is LwipException lwipEx) || lwipEx.LwipCode != -14) // lwIP Reset
                           {
                               DebugLogger.Log($"Send error: {Destination}: {ex}");
                           }
                       }
                       return t;
                   }).Unwrap()
                ).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception)
            {
                // Something wrong happened during recv/send and was handled separatedly.
                DebugLogger.Log("Reset!: " + Destination);
                Reset();
            }
            finally
            {
                if (remoteAdapter != null)
                {
                    remoteAdapter.RemoteDisconnected = true;
                }
                recvCancel.Dispose();
                sendCancel.Dispose();
            }
            CheckShutdown();
        }

        protected void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            DebugLogger.Log("Socket error " + err.ToString());
            if (remoteAdapter?.RemoteDisconnected == false)
            {
                remoteAdapter?.FinishSendToRemote(new LwipException(err));
            }
            if (localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        protected void Socket_DataSent (TcpSocket sender, ushort length, ushort buflen)
        {
            // Interlocked.Add(ref localStackByteCount, length);
            localStackByteCount = buflen;
            Interlocked.Add(ref localPendingByteCount, -length);
            if (localStackBufLock.CurrentCount == 0)
            {
                try
                {
                    localStackBufLock.Release();
                }
                catch (SemaphoreFullException) { }
            }
            if (pollCancelSource == null && localWriteFinishLock?.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
        }

        protected void Socket_DataReceived (TcpSocket sender, byte[] bytes)
        {
            remoteAdapter?.SendToRemote(bytes);
        }

        private void Socket_RecvFinished (TcpSocket sender)
        {
            // Local FIN recved
            if (remoteAdapter?.RemoteDisconnected == false)
            {
                remoteAdapter.FinishSendToRemote();
            }
        }

        public Task Close ()
        {
            if (Interlocked.Exchange(ref IsShutdown, 1) == 1)
            {
                return Task.FromResult(0);
            }
            pollCancelSource?.Cancel();
            return _tun.executeLwipTask(() => _socket.Close());
        }

        public void Reset ()
        {
            if (Interlocked.Exchange(ref IsShutdown, 1) == 1)
            {
                return;
            }
            pollCancelSource?.Cancel();
            _tun.executeLwipTask(() => _socket.Abort());
        }

        public void ConfirmRecvFromLocal (ushort len)
        {
            _tun.executeLwipTask(() => _socket.Recved(len));
        }

        public Task FinishInbound ()
        {
            pipeWriter.Complete();
            if (pollCancelSource != null || localPendingByteCount != 0)
            {
                return localWriteFinishLock.WaitAsync();
            }
            return Task.CompletedTask;
        }

        public Span<byte> GetSpanForWriteToLocal (int sizeHint = 0)
        {
            return pipeWriter.GetSpan(sizeHint);
        }

        public Task FlushToLocal (int byteCount, CancellationToken cancellationToken = default)
        {
            pipeWriter.Advance(byteCount);
            return pipeWriter.FlushAsync(cancellationToken).AsTask();
        }

        public Task WriteToLocal (Span<byte> e, CancellationToken cancellationToken = default)
        {
            var memory = pipeWriter.GetSpan(e.Length);
            e.CopyTo(memory);
            pipeWriter.Advance(e.Length);
            return pipeWriter.FlushAsync(cancellationToken).AsTask();
        }

        public virtual void CheckShutdown ()
        {
            Interlocked.Decrement(ref OpenCount);
            _socket.DataReceived -= Socket_DataReceived;
            _socket.DataSent -= Socket_DataSent;
            _socket.SocketError -= Socket_SocketError;
            _socket.RecvFinished -= Socket_RecvFinished;
            Interlocked.Exchange(ref localStackBufLock, null).Dispose();
            Interlocked.Exchange(ref localWriteFinishLock, null).Dispose();
            remoteAdapter?.CheckShutdown();
        }
    }
}
