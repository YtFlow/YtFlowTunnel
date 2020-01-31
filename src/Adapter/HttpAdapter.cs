using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    internal sealed class HttpAdapter : ProxyAdapter
    {
        private static readonly byte[] HEADER1 = Encoding.UTF8.GetBytes("CONNECT ");
        private static readonly byte[] HEADER2 = Encoding.UTF8.GetBytes(" HTTP/1.1\r\n\r\n");
        private const int RECV_BUFFER_LEN = 1024;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork);
        NetworkStream networkStream;
        // IInputStream networkReadStream;
        // IOutputStream networkWriteStream;
        string server;
        int port;
        private ConcurrentQueue<byte[]> localbuf = new ConcurrentQueue<byte[]>();
        private bool remoteConnected = false;

        public HttpAdapter (string srv, int port, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            server = srv;
            this.port = port;

            Init();
        }

        public async void Init ()
        {
            var connectTask = r.ConnectAsync(server, port);
            string domain = DnsProxyServer.Lookup(_socket.RemoteAddr);
            if (domain == null)
            {
                Debug.WriteLine("Cannot find DNS record");
                FinishSendToRemote();
                Reset();
                return;
            }
            string portStr = _socket.RemotePort.ToString();
            byte[] portBytes = Encoding.UTF8.GetBytes(portStr);
            byte[] domainBytes = Encoding.UTF8.GetBytes(domain);
            int headerLen = HEADER1.Length + domainBytes.Length + 1 + portBytes.Length + HEADER2.Length;
            byte[] firstSeg = new byte[headerLen];
            HEADER1.CopyTo(firstSeg, 0);
            domainBytes.CopyTo(firstSeg, HEADER1.Length);
            firstSeg[HEADER1.Length + domainBytes.Length] = (byte)':';
            portBytes.CopyTo(firstSeg, HEADER1.Length + domainBytes.Length + 1);
            HEADER2.CopyTo(firstSeg, headerLen - HEADER2.Length);

            try
            {
                await connectTask;
                Debug.WriteLine("Connected");
                networkStream = r.GetStream();
                await networkStream.WriteAsync(firstSeg, 0, headerLen);
                byte[] responseBuf = new byte[RECV_BUFFER_LEN];
                var responseLen = await networkStream.ReadAsync(responseBuf, 0, 100);
                if (responseLen < 14)
                {
                    throw new InvalidOperationException("Remote response too short.");
                }
                if ((responseBuf[9] == (byte)'2') && (responseBuf[10] == (byte)'0') && (responseBuf[11] == (byte)'0'))
                {
                    // 200 objk
                }
                else
                {
                    throw new InvalidOperationException("Remote connection cannot be established.");
                }
                bool foundHeader = false;
                int headerStart;
                for (headerStart = 12; headerStart < responseLen - 3; headerStart++)
                {
                    if (responseBuf[headerStart] == '\r')
                    {
                        if (responseBuf[headerStart + 1] == '\n')
                        {
                            if (responseBuf[headerStart + 2] == '\r')
                            {
                                if (responseBuf[headerStart + 3] == '\n')
                                {
                                    foundHeader = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (!foundHeader)
                {
                    throw new InvalidOperationException("Unrecognized remote header.");
                }
                headerStart += 4;
                if (headerStart >= responseLen)
                {
                    // No initial data
                }
                else
                {
                    await RemoteReceived(responseBuf.AsSpan(headerStart, responseLen));
                }

                int bytesToConfirm = 0;
                while (localbuf.TryDequeue(out var buf))
                {
                    bytesToConfirm += buf.Length;
                    // await networkWriteStream.WriteAsync(await Encrypt(buf));
                    await networkStream.WriteAsync(buf, 0, buf.Length);
                }
                remoteConnected = true;
                if (bytesToConfirm > 0)
                {
                    Recved((ushort)bytesToConfirm);
                }
                //await networkWriteStream.FlushAsync();
                Debug.WriteLine("Sent data with header");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error sending header to remote" + ex.Message);
                FinishSendToRemote();
                Reset();
                return;
            }

            // IBuffer remotebuf = WindowsRuntimeBuffer.Create(RECV_BUFFER_LEN);
            byte[] remotebuf = new byte[RECV_BUFFER_LEN];
            while (r.Connected && networkStream.CanRead)
            {
                try
                {
                    var len = await networkStream.ReadAsync(remotebuf, 0, RECV_BUFFER_LEN).ConfigureAwait(false);
                    if (len == 0)
                    {
                        break;
                    }
#if YTLOG_VERBOSE
                    Debug.WriteLine($"Received {len} bytes");
#endif

                    await RemoteReceived(remotebuf.AsSpan(0, len));
                }
                catch (Exception)
                {
                    break;
                }
            }

            try
            {
                Debug.WriteLine("Remote sent no data");
                // networkReadStream?.Dispose();
                r?.Client?.Shutdown(SocketShutdown.Receive);
                Close();
            }
            catch (Exception) { }
        }

        protected override async void FinishSendToRemote (Exception ex = null)
        {
            try
            {
                if (!localbuf.IsEmpty)
                {
                    while (localbuf.TryDequeue(out var buf))
                    {
                        await networkStream?.WriteAsync(buf, 0, buf.Length);
                    }
                    await networkStream?.FlushAsync();
                }
            }
            catch (Exception) { }
            try
            {
                // networkWriteStream?.Dispose();
                r?.Client?.Shutdown(SocketShutdown.Send);
                Debug.WriteLine("Disposed remote write stream");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error closing remote write stream");
            }
            RemoteDisconnected = true;
            CheckShutdown();
            // try
            // {
            //     r.Dispose();
            //     Debug.WriteLine("remote socket disposed");
            // }
            // catch (Exception)
            // {
            //     Debug.WriteLine("remote socket already disposed");
            // }
        }

        protected override async void SendToRemote (byte[] buffer)
        {
            if (remoteConnected)
            {
                try
                {
                    await networkStream.WriteAsync(buffer, 0, buffer.Length);
                    await networkStream.FlushAsync();
                    Recved((ushort)buffer.Length);
#if YTLOG_VERBOSE
                    Debug.WriteLine("Sent data" + buffer.Length);
#endif
                    // r.Send(e);
                }
                catch (Exception)
                {
                    Debug.WriteLine("Cannot send to remote");
                }
            }
            else
            {
                // buffer.CopyTo(0, localbuf, localbuf.Length, buffer.Length);
                // localbuf.Length += buffer.Length;
                localbuf.Enqueue(buffer);
#if YTLOG_VERBOSE
                Debug.WriteLine("Queued data" + buffer.Length);
#endif
            }
        }

        protected override void CheckShutdown ()
        {
            networkStream?.Dispose();
            r?.Dispose();
            base.CheckShutdown();
        }
    }
}
