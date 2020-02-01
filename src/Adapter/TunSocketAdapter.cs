using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;
using Wintun2socks;

namespace YtFlow.Tunnel
{
    internal abstract class TunSocketAdapter : IAdapterSocket
    {
        protected TcpSocket _socket;
        protected TunInterface _tun;
        protected PipeReader pipeReader;
        protected PipeWriter pipeWriter;
        private CancellationTokenSource pollCancelSource = new CancellationTokenSource();
        private SemaphoreSlim localStackBufLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim localWriteFinishLock = new SemaphoreSlim(0, 1);
        private int localStackByteCount = 11680;
        private int localPendingByteCount = 0;
        public int IsShutdown = 0;
        public event ReadDataHandler ReadData;
        public event SocketErrorHandler OnError;
        public event SocketFinishedHandler OnFinished;

        internal TunSocketAdapter (TcpSocket socket, TunInterface tun)
        {
            var pipe = new Pipe();
            pipeReader = pipe.Reader;
            pipeWriter = pipe.Writer;
            _socket = socket;
            _tun = tun;

            socket.DataReceived += Socket_DataReceived;
            socket.DataSent += Socket_DataSent;
            socket.SocketError += Socket_SocketError;
            socket.RecvFinished += Socket_RecvFinished;

            StartPolling();
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
            int _localStackByteCount;
            // Wait until there is enough space in the stack
            while ((_localStackByteCount = localStackByteCount) <= 1600)
            {
                await localStackBufLock.WaitAsync(pollCancelSource.Token).ConfigureAwait(false);
            }
            var start = buffer.Start;
            // A buffer may consist of several Memory<byte> chunks,
            // read one of them at a time.
            if (!buffer.TryGet(ref start, out var chunk))
            {
                pipeReader.Complete(new InvalidOperationException("Got an empty segment to write to local"));
                return false;
            }
            var more = buffer.Length == _localStackByteCount || buffer.Length != chunk.Length;
            byte writeResult;
            using (var dataHandle = chunk.Pin())
            {
                writeResult = await SendToSocket(dataHandle, (ushort)chunk.Length, more);
                while (writeResult == 255)
                {
                    if (!await (localStackBufLock?.WaitAsync(3000, pollCancelSource.Token).ConfigureAwait(false) ?? Task.FromResult(false).ConfigureAwait(false)))
                    {
                        DebugLogger.Log("Local write timeout");
                        break;
                    }
                    writeResult = await SendToSocket(dataHandle, (ushort)chunk.Length, more);
                }
            }
            if (writeResult != 0)
            {
                DebugLogger.Log("Error from writing to local socket:" + writeResult.ToString());
                OnError?.Invoke(this, writeResult);
                return false;
            }
            Interlocked.Add(ref localStackByteCount, -chunk.Length);
            Interlocked.Add(ref localPendingByteCount, chunk.Length);
            pipeReader.AdvanceTo(buffer.GetPosition(chunk.Length));
            // await _tun.executeLwipTask(() => _socket.Output());

            if (readResult.IsCanceled || (readResult.IsCompleted && chunk.Length == buffer.Length) || writeResult != 0 || pollCancelSource.IsCancellationRequested)
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

        protected void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            DebugLogger.Log("Socket error " + err.ToString());
            OnError?.Invoke(this, err);
            if (localWriteFinishLock.CurrentCount == 0)
            {
                localWriteFinishLock.Release();
            }
            // IsShutdown = 1;
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
            ReadData?.Invoke(this, bytes);
        }

        private void Socket_RecvFinished (TcpSocket sender)
        {
            // Local FIN recved
            OnFinished?.Invoke(this);
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

        protected Span<byte> GetSpanForWriteToLocal (int sizeHint = 0)
        {
            return pipeWriter.GetSpan(sizeHint);
        }

        public Task FlushToLocal (int byteCount)
        {
            pipeWriter.Advance(byteCount);
            return pipeWriter.FlushAsync().AsTask();
        }

        public Task WriteToLocal (Span<byte> e)
        {
            var memory = pipeWriter.GetSpan(e.Length);
            e.CopyTo(memory);
            pipeWriter.Advance(e.Length);
            return pipeWriter.FlushAsync().AsTask();
        }

        protected virtual void CheckShutdown ()
        {
            _socket.DataReceived -= Socket_DataReceived;
            _socket.DataSent -= Socket_DataSent;
            _socket.SocketError -= Socket_SocketError;
            _socket.RecvFinished -= Socket_RecvFinished;
            Interlocked.Exchange(ref localStackBufLock, null).Dispose();
            Interlocked.Exchange(ref localWriteFinishLock, null).Dispose();
        }
    }
}
