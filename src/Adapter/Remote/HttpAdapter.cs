using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal sealed class HttpAdapter : IRemoteAdapter
    {
        private static readonly byte[] HEADER1 = Encoding.UTF8.GetBytes("CONNECT ");
        private static readonly byte[] HEADER2 = Encoding.UTF8.GetBytes(" HTTP/1.1\r\n\r\n");
        private readonly string server;
        private readonly int port;
        private const int RECV_BUFFER_LEN = 1024;
        private const int HEAD_BUFFER_LEN = 100;
        private TcpClient client = new TcpClient(AddressFamily.InterNetwork);
        private NetworkStream networkStream;
        private ILocalAdapter localAdapter;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });
        public bool RemoteDisconnected { get; set; } = false;

        public HttpAdapter (string server, int port)
        {
            this.server = server;
            this.port = port;
        }

        public async Task Init (ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;
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
            if (DebugLogger.InitNeeded())
            {
                DebugLogger.Log("Connected: " + destination.ToString());
            }
            networkStream = client.GetStream();
            await networkStream.WriteAsync(firstSeg, 0, headerLen).ConfigureAwait(false);
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
                var _ = localAdapter.WriteToLocal(responseBuf.AsSpan(headerStart, responseLen));
            }
        }

        public void FinishSendToRemote (Exception ex = null)
        {
            outboundChan.Writer.TryComplete(ex);
        }

        public async void SendToRemote (byte[] buffer)
        {
            if (outboundChan != null)
            {
                await outboundChan.Writer.WriteAsync(buffer).ConfigureAwait(false);
            }
        }

        public async Task StartSend (CancellationToken cancellationToken = default)
        {
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
                // TODO: batch write
                await networkStream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
                // await networkStream.FlushAsync();
                localAdapter.ConfirmRecvFromLocal((ushort)data.Length);
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Send);
        }

        public async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (client.Connected && networkStream.CanRead)
            {
                var len = await networkStream.ReadAsync(buf, 0, RECV_BUFFER_LEN, cancellationToken).ConfigureAwait(false);
                if (len == 0)
                {
                    break;
                }
                await localAdapter.WriteToLocal(buf.AsSpan(0, len), cancellationToken).ConfigureAwait(false);
            }
        }

        public void CheckShutdown ()
        {
            networkStream?.Dispose();
            client?.Dispose();
        }
    }
}
