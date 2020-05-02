using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal sealed class HttpAdapter : IRemoteAdapter
    {
        private static readonly byte[] HEADER1 = Encoding.UTF8.GetBytes("CONNECT ");
        private static readonly byte[] HEADER2 = Encoding.UTF8.GetBytes(" HTTP/1.1\r\n\r\n");
        private static readonly NotSupportedException UdpNotSupportedException = new NotSupportedException("UDP destination is not supported");
        private readonly string server;
        private readonly int port;
        private const int HEAD_BUFFER_LEN = 100;
        private readonly TcpClient client = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true
        };
        private NetworkStream networkStream;
        public bool RemoteDisconnected { get; set; } = false;

        public HttpAdapter (string server, int port)
        {
            this.server = server;
            this.port = port;
        }

        public async ValueTask Init (ChannelReader<byte[]> outboundChan, ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            if (localAdapter.Destination.TransportProtocol == TransportProtocol.Udp)
            {
                throw UdpNotSupportedException;
            }
            var connectTask = client.ConnectAsync(server, port).ConfigureAwait(false);
            var destination = localAdapter.Destination;
            string portStr = destination.Port.ToString();
            byte[] portBytes = Encoding.UTF8.GetBytes(portStr);
            byte[] domainBytes = new byte[destination.Host.Size];
            destination.Host.CopyTo(domainBytes);
            int headerLen = HEADER1.Length + domainBytes.Length + 1 + portBytes.Length + HEADER2.Length;
            byte[] firstSeg = new byte[headerLen];
            HEADER1.CopyTo(firstSeg, 0);
            domainBytes.CopyTo(firstSeg, HEADER1.Length);
            firstSeg[HEADER1.Length + domainBytes.Length] = (byte)':';
            portBytes.CopyTo(firstSeg, HEADER1.Length + domainBytes.Length + 1);
            HEADER2.CopyTo(firstSeg, headerLen - HEADER2.Length);

            // Connect and perform handshake
            await connectTask;
            networkStream = client.GetStream();
            await networkStream.WriteAsync(firstSeg, 0, headerLen, cancellationToken).ConfigureAwait(false);
            byte[] responseBuf = new byte[HEAD_BUFFER_LEN];
            var responseLen = await networkStream.ReadAsync(responseBuf, 0, HEAD_BUFFER_LEN, cancellationToken);
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
            // Initial data?
            client.NoDelay = false;
        }

        public async Task StartSend (ChannelReader<byte[]> outboundChan, CancellationToken cancellationToken = default)
        {
            while (await outboundChan.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (outboundChan.TryRead(out var data))
                {
                    // TODO: batch write
                    await networkStream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
                    // await networkStream.FlushAsync();
                }
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Send);
        }

        public ValueTask<int> GetRecvBufSizeHint (int preferredSize, CancellationToken cancellationToken = default) => new ValueTask<int>(preferredSize);

        public async ValueTask<int> StartRecv (ArraySegment<byte> outBuf, CancellationToken cancellationToken = default)
        {
            var len = await networkStream.ReadAsync(outBuf.Array, outBuf.Offset, outBuf.Count, cancellationToken).ConfigureAwait(false);
            if (len == 0)
            {
                return 0;
            }
            return len;
        }

        public void CheckShutdown ()
        {
            try
            {
                networkStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            try
            {
                client?.Dispose();
            }
            catch (ObjectDisposedException) { }
        }

        public Task StartRecvPacket (ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public void SendPacketToRemote (Memory<byte> data, Destination.Destination destination)
        {
        }
    }
}
