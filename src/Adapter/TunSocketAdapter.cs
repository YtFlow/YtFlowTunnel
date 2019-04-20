using System;
using System.Collections.Concurrent;
using System.Diagnostics;
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
        const int MAX_BUFF_SIZE = 2048;
        protected TcpSocket _socket;
        protected TunInterface _tun;
        protected BlockingCollection<IBuffer> sendBuffers = new BlockingCollection<IBuffer>(1024);
        private Task sendBufferTask;
        private bool sendBufferFinished = false;
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
            _socket = socket;
            _tun = tun;

            socket.DataReceived += Socket_DataReceived;
            socket.DataSent += Socket_DataSent;
            socket.SocketError += Socket_SocketError;

            sendBufferTask = Task.Run(async () =>
            {
                while (!sendBufferFinished && !sendBuffers.IsAddingCompleted)
                {
                    IBuffer buf;
                    try
                    {
                        buf = await Task.Run(() => sendBuffers.Take());
                    }
                    catch (InvalidOperationException)
                    {
#if YTLOG_VERBOSE
                        Debug.WriteLine("No data sent to local");
#endif
                        break;
                    }
                    var result = await _tun.executeLwipTask(() => _socket.Send(buf.ToArray()));
                    while (result != 0 && !sendBufferFinished)
                    {
                        await Task.Delay(10);
                        result = await _tun.executeLwipTask(() => _socket.Send(buf.ToArray()));
                    }
                    Debug.WriteLine("Data sent to local");
                    /*if (sendBuffers.Count == 0)
                    {
                        await _tun.executeLwipTask(() => _socket.Output());
                    }*/
                }
            });
        }

        private void checkSendBuffers ()
        {
            // checkSendBufferHandle.Set();
        }

        protected virtual void Socket_SocketError (TcpSocket sender, int err)
        {
            // tcp_pcb has been freed already
            // No need to close
            // Close();
            OnError?.Invoke(this, err);
        }

        protected virtual void Socket_DataSent (TcpSocket sender, ushort length)
        {
            checkSendBuffers();
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
                checkSendBuffers();
            }
        }

        public virtual void Close ()
        {
            // _tun.executeLwipTask(() => _socket.Close());
            Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            finishSendBuffer();
        }

        public virtual void Reset ()
        {
            _tun.executeLwipTask(() => _socket.Abort());
            finishSendBuffer();
        }

        private void finishSendBuffer ()
        {
            sendBufferFinished = true;
            sendBuffers.CompleteAdding();
            // checkSendBufferHandle.Set();
        }

        public virtual void Write (IBuffer e)
        {
            //for (int i = 0; i < bytes.Length; i += MAX_BUFF_SIZE)
            //{
            //    sendBuffers.Enqueue(bytes.AsBuffer(i, Math.Min(bytes.Length - i, MAX_BUFF_SIZE)));
            //    checkSendBuffers();
            //}

            try
            {
                sendBuffers.TryAdd(e);
            }
            catch (Exception)
            {
                ;
            }
            // checkSendBuffers();
            // return _tun.executeLwipTask(() => _socket.Send(e.ToArray()));
        }
    }
}
