using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Wintun2socks;

namespace YtFlow.Tunnel
{
    internal abstract class TunSocketAdapter : IAdapterSocket
    {
        //const int MAX_BUFF_SIZE = 2048;
        protected TcpSocket _socket;
        protected TunInterface _tun;
        //protected BlockingCollection<IBuffer> sendBuffers = new BlockingCollection<IBuffer>(1024);
        //private Task sendBufferTask;
        //private bool sendBufferFinished = false;
        protected PipeReader pipeReader;
        protected PipeWriter pipeWriter;
        protected bool LocalDisconnecting { get; set; } = false;
        protected bool LocalDisconnected { get; set; } = false;
        private bool readCompleted = false;
        protected SemaphoreSlim localStackBufLock = new SemaphoreSlim(1, 1);
        private int localStackByteCount = 11680;
        private int localPendingByteCount = 0;
        public virtual bool IsShutdown { get; }
        public event ReadDataHandler ReadData;
        public event SocketErrorHandler OnError;
        public event SocketFinishedHandler OnFinished;

        public static void LogData (string prefix, byte[] data)
        {
            /*var sb = new StringBuilder(data.Length * 6 + prefix.Length);
            sb.Append(prefix);
            sb.Append(Encoding.ASCII.GetString(data));
            sb.Append(" ");
            foreach (var by in data)
            {
                sb.AppendFormat("\\x{0:x2} ", by);
            }

            Debug.WriteLine(sb.ToString());*/
        }

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

            StartPolling();
        }

        private async Task<bool> PollOne ()
        {
            var readResult = await pipeReader.ReadAsync().ConfigureAwait(false);
            var buffer = readResult.Buffer;
            if (buffer.Length == 0)
            {
                return false;
            }
            int _localStackByteCount;
            while ((_localStackByteCount = localStackByteCount) <= 0 && !LocalDisconnected)
            {
                await localStackBufLock.WaitAsync().ConfigureAwait(false);
            }
            ReadOnlySequence<byte> chunk = buffer.Slice(0, Math.Min(buffer.Length, _localStackByteCount));
            var arr = chunk.ToArray();
            var more = chunk.Length == _localStackByteCount;
            var writeResult = await _tun.executeLwipTask(() => _socket.Send(arr, more));
            while (writeResult == 255 && !LocalDisconnected)
            {
                if (!await localStackBufLock.WaitAsync(1000).ConfigureAwait(false))
                {
                    DebugLogger.Log("Local write timeout");
                    break;
                }
                writeResult = await _tun.executeLwipTask(() => _socket.Send(arr, more));
            }
            if (writeResult != 0)
            {
                DebugLogger.Log("Error from writing:");
                OnError?.Invoke(this, writeResult);
                pipeReader.Complete();
                return false;
            }
            Interlocked.Add(ref localStackByteCount, (int)-chunk.Length);
            Interlocked.Add(ref localPendingByteCount, (int)chunk.Length);
            pipeReader.AdvanceTo(chunk.End, chunk.End);
            // await _tun.executeLwipTask(() => _socket.Output());

            if (readResult.IsCanceled || readResult.IsCompleted || writeResult != 0)
            {
                return false;
            }
            return true;
        }

        private void PollComplete ()
        {
            readCompleted = true;
            pipeReader.Complete();
            // await _tun.executeLwipTask(() => _socket.Close());
            // Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            // LocalDisconnected = true;
            OnFinished?.Invoke(this);
            // CheckShutdown();
        }

        private async void StartPolling ()
        {
            localStackByteCount = await _tun.executeLwipTask(() => _socket.SendBufferSize);
            while (await PollOne()) { }
            PollComplete();
        }

        protected virtual void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            DebugLogger.Log("Socket error " + err.ToString());
            LocalDisconnecting = LocalDisconnected = false;
            OnError?.Invoke(this, err);
            CheckShutdown();
        }

        protected virtual async void Socket_DataSent (TcpSocket sender, ushort length, ushort buflen)
        {
            // Interlocked.Add(ref localStackByteCount, length);
            localStackByteCount = buflen;
            if (localStackBufLock.CurrentCount == 0)
            {
                try
                {
                    localStackBufLock.Release();
                }
                catch (SemaphoreFullException) { }
            }
            Interlocked.Add(ref localPendingByteCount, -length);
            if (localPendingByteCount == 0 && readCompleted)
            {
                LocalDisconnected = true;
                await _tun.executeLwipTask(() => _socket.Close());
                CheckShutdown();
            }
        }

        protected virtual void Socket_DataReceived (TcpSocket sender, byte[] bytes)
        {
            if (bytes == null)
            {
                // Local FIN recved??
                Close();
                OnFinished?.Invoke(this);
            }
            else
            {
                ReadData(this, bytes);
            }
        }

        public virtual void Close ()
        {
            LocalDisconnecting = LocalDisconnected = true;
            pipeWriter.Complete();
        }

        public virtual void Reset ()
        {
            DebugLogger.Log("Reset");
            LocalDisconnecting = LocalDisconnected = true;
            OnError?.Invoke(this, 1);
            CheckShutdown();
        }

        public void Recved (ushort len)
        {
            _tun.executeLwipTask(() => _socket.Recved(len));
        }

        public virtual async Task Write (Memory<byte> e)
        {
            var memory = pipeWriter.GetMemory(e.Length);
            e.CopyTo(memory);
            pipeWriter.Advance(e.Length);
            await pipeWriter.FlushAsync();
            // checkSendBuffers();
        }

        protected virtual void CheckShutdown ()
        {
            if (IsShutdown)
            {
                _socket.DataReceived -= Socket_DataReceived;
                _socket.DataSent -= Socket_DataSent;
                _socket.SocketError -= Socket_SocketError;
                localStackBufLock?.Dispose();
            }
        }
    }
}
