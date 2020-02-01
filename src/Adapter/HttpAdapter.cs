using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    internal sealed class HttpAdapter : ProxyAdapter
    {
        private static readonly byte[] HEADER1 = Encoding.UTF8.GetBytes("CONNECT ");
        private static readonly byte[] HEADER2 = Encoding.UTF8.GetBytes(" HTTP/1.1\r\n\r\n");
        private const int RECV_BUFFER_LEN = 1024;
        private const int HEAD_BUFFER_LEN = 100;
        TcpClient client = new TcpClient(AddressFamily.InterNetwork);
        NetworkStream networkStream;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });

        public HttpAdapter (string server, int port, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            Init(server, port);
        }

        public async void Init (string server, int port)
        {
            string domain = DnsProxyServer.Lookup(_socket.RemoteAddr);
            if (domain == null)
            {
                RemoteDisconnected = true;
                DebugLogger.Log("Cannot find DNS record");
                Reset();
                CheckShutdown();
                return;
            }
            var connectTask = client.ConnectAsync(server, port);
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

            // Connect and perform handshake
            try
            {
                await connectTask;
                DebugLogger.Log("Connected: " + domain);
                networkStream = client.GetStream();
                await networkStream.WriteAsync(firstSeg, 0, headerLen);
                byte[] responseBuf = new byte[HEAD_BUFFER_LEN];
                var responseLen = await networkStream.ReadAsync(responseBuf, 0, HEAD_BUFFER_LEN);
                if (responseLen < 14)
                {
                    throw new InvalidOperationException("Remote response too short");
                }
                if ((responseBuf[9] == (byte)'2') && (responseBuf[10] == (byte)'0') && (responseBuf[11] == (byte)'0'))
                {
                    // 200 objk
                }
                else
                {
                    var code = 100 * (responseBuf[9] - '0') + 10 * (responseBuf[10] - '0') + responseBuf[11] - '0';
                    throw new InvalidOperationException("Remote status code: " + code.ToString());
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
                    throw new InvalidOperationException("Unrecognized remote header: " + Encoding.UTF8.GetString(responseBuf, 0, responseLen));
                }
                headerStart += 4;
                if (headerStart >= responseLen)
                {
                    // No initial data
                }
                else
                {
                    var _ = RemoteReceived(responseBuf.AsSpan(headerStart, responseLen));
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error sending header: {domain}: " + ex.ToString());
                CheckShutdown();
                Reset();
                return;
            }

            await StartForward(domain);
        }

        protected override void FinishSendToRemote (Exception ex = null)
        {
            outboundChan.Writer.TryComplete(ex);
        }

        protected override async void SendToRemote (byte[] buffer)
        {
            if (outboundChan != null)
            {
                await outboundChan.Writer.WriteAsync(buffer);
            }
        }

        protected override async Task StartSend (CancellationToken cancellationToken = default)
        {
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
                // TODO: batch write
                await networkStream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
                // await networkStream.FlushAsync();
                ConfirmRecvFromLocal((ushort)data.Length);
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Send);
        }

        protected override async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (client.Connected && networkStream.CanRead)
            {
                var len = await networkStream.ReadAsync(buf, 0, RECV_BUFFER_LEN, cancellationToken).ConfigureAwait(false);
                if (len == 0)
                {
                    break;
                }
                await WriteToLocal(buf.AsSpan(0, len)).ConfigureAwait(false);
            }
            await FinishInbound().ConfigureAwait(false);
        }

        protected override void CheckShutdown ()
        {
            networkStream?.Dispose();
            client?.Dispose();
            base.CheckShutdown();
        }
    }
}
