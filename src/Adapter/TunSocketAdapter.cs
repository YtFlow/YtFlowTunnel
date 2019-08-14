using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage.Streams;
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
        protected SemaphoreSlim localStackBufLock = new SemaphoreSlim(1, 1);
        private int localStackByteCount = 11680;
        // private int localStackTrunkSize = 4096;
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

        /// <deprecated>
        /// Not used. For reference only.
        /// </deprecated>
        private async void StartPolling1 ()
        {
            while (true)
            {
                var readResult = await pipeReader.ReadAsync().ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = readResult.Buffer;
                SequencePosition? position = buffer.Start;
                var remainingBytes = buffer.Length;
                var writeResult = (byte)0;
                while (remainingBytes > 0)
                {
                    while (localStackByteCount == 0)
                    {
                        await _tun.executeLwipTask(() => _socket.Output());
                        await localStackBufLock.WaitAsync().ConfigureAwait(false);
                    }
                    var bytesToWriteCount = Math.Min(remainingBytes, localStackByteCount);
                    var chunk = buffer.Slice(position.Value, bytesToWriteCount);
                    var arr = chunk.ToArray();
                    var more = remainingBytes != bytesToWriteCount;
                    writeResult = await _tun.executeLwipTask(() => _socket.Send(arr, more));
                    if (writeResult != 0)
                    {
                        OnError?.Invoke(this, writeResult);
                        pipeReader.Complete();
                        return;
                    }
                    remainingBytes -= bytesToWriteCount;
                    position = buffer.GetPosition(bytesToWriteCount, position.Value);
                    Interlocked.Add(ref localStackByteCount, (int)-bytesToWriteCount);
                }
                pipeReader.AdvanceTo(position.Value, position.Value);
                await _tun.executeLwipTask(() => _socket.Output());

                if (readResult.IsCanceled || readResult.IsCompleted || writeResult != 0)
                {
                    break;
                }
            }
            pipeReader.Complete();
            await _tun.executeLwipTask(() => _socket.Close());
            Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            LocalDisconnected = true;
            OnFinished(this);
            CheckShutdown();
        }

        private async void StartPolling ()
        {
            localStackByteCount = await _tun.executeLwipTask(() => _socket.SendBufferSize);
            while (true)
            {
                var readResult = await pipeReader.ReadAsync().ConfigureAwait(false);
                var buffer = readResult.Buffer;
                if (buffer.Length == 0)
                {
                    break;
                }
                ReadOnlySequence<byte> chunk = buffer.Slice(0, Math.Min(buffer.Length, localStackByteCount));
                var arr = chunk.ToArray();
                var more = chunk.Length == localStackByteCount;
                var writeResult = await _tun.executeLwipTask(() => _socket.Send(arr, more));
                if (writeResult != 0)
                {
                    OnError?.Invoke(this, writeResult);
                    pipeReader.Complete();
                    return;
                }
                Interlocked.Add(ref localStackByteCount, (int)-chunk.Length);
                pipeReader.AdvanceTo(chunk.End, chunk.End);
                // await _tun.executeLwipTask(() => _socket.Output());

                if (readResult.IsCanceled || readResult.IsCompleted || writeResult != 0)
                {
                    break;
                }
            }
            pipeReader.Complete();
            await _tun.executeLwipTask(() => _socket.Close());
            Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            LocalDisconnected = true;
            OnFinished(this);
            CheckShutdown();
        }

        protected virtual void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            LocalDisconnecting = LocalDisconnected = false;
            OnError?.Invoke(this, err);
            CheckShutdown();
        }

        protected virtual void Socket_DataSent (TcpSocket sender, ushort length)
        {
            Interlocked.Add(ref localStackByteCount, length);
            if (localStackBufLock.CurrentCount == 0)
            {
                localStackBufLock.Release();
            }
        }

        protected virtual void Socket_DataReceived (TcpSocket sender, byte[] bytes)
        {
            if (bytes == null)
            {
                // Local FIN recved
                // Close();
                OnFinished?.Invoke(this);
            }
            else
            {
                ReadData(this, bytes);
            }
        }

        public virtual void Close ()
        {
            // _tun.executeLwipTask(() => _socket.Close());
            LocalDisconnecting = true;
            pipeWriter.Complete();
        }

        public virtual void Reset ()
        {
            LocalDisconnecting = LocalDisconnected = true;
            _tun.executeLwipTask(() => _socket.Abort());
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
                localStackBufLock.Dispose();
            }
        }
    }
}
