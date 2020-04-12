using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage.Streams;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    /// <summary>
    /// Trojan adapter
    /// </summary>
    internal sealed class TrojanAdapter : IRemoteAdapter
    {
        private static readonly ArrayPool<byte> sendArrayPool = ArrayPool<byte>.Create();
        private readonly HostName server;
        private readonly string port;
        private readonly Memory<byte> hashedPassword;
        private readonly bool allowInsecure;
        private readonly StreamSocket socket = new StreamSocket();
        private IInputStream inputStream;
        private IOutputStream outputStream;
        public bool RemoteDisconnected { get; set; }

        public TrojanAdapter (HostName server, string port, Memory<byte> hashedPassword, bool allowInsecure)
        {
            this.server = server;
            this.port = port;
            this.hashedPassword = hashedPassword;
            this.allowInsecure = allowInsecure;
        }

        public int FillTrojanRequest (Span<byte> data, Destination.Destination destination, bool isUdpPayload = false, ushort udpPayloadSize = 0)
        {
            Span<byte> crlf = stackalloc byte[2];
            crlf[0] = 0x0D;
            crlf[1] = 0x0A;
            int len = 0;
            if (!isUdpPayload)
            {
                hashedPassword.Span.CopyTo(data);
                len += hashedPassword.Length;
                crlf.CopyTo(data.Slice(len, 2));
                len += crlf.Length;
                switch (destination.TransportProtocol)
                {
                    case TransportProtocol.Tcp:
                        data[len++] = 1;
                        break;
                    case TransportProtocol.Udp:
                        data[len++] = 3;
                        break;
                }
            }
            len += destination.FillSocks5StyleAddress(data.Slice(len));
            if (isUdpPayload)
            {
                data[len++] = (byte)(udpPayloadSize >> 8);
                data[len++] = (byte)(udpPayloadSize & 0xFF);
            }
            crlf.CopyTo(data.Slice(len));
            len += 2;
            return len;
        }

        public async ValueTask Init (ChannelReader<byte[]> outboundChan, ILocalAdapter localAdapter)
        {
            if (allowInsecure)
            {
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.IncompleteChain);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
            }
            var dev = NetworkInformation.GetInternetConnectionProfile().NetworkAdapter;
            var connectTask = socket.ConnectAsync(server, port, SocketProtectionLevel.Tls12, dev).AsTask().ConfigureAwait(false);
            // TODO: custom certificate, server name

            var destination = localAdapter.Destination;
            var firstBuf = Array.Empty<byte>();
            var firstBufCancel = new CancellationTokenSource(500);
            try
            {
                if (await outboundChan.WaitToReadAsync(firstBufCancel.Token).ConfigureAwait(false))
                {
                    outboundChan.TryRead(out firstBuf);
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                firstBufCancel.Dispose();
            }
            int firstBufLen = firstBuf.Length;
            byte[] requestPayload = sendArrayPool.Rent(destination.Host.Size + firstBufLen + 65);
            try
            {
                var headerLen = FillTrojanRequest(requestPayload, destination);
                firstBuf.CopyTo(requestPayload.AsSpan(headerLen));

                await connectTask;
                inputStream = socket.InputStream;
                outputStream = socket.OutputStream;
                await outputStream.WriteAsync(requestPayload.AsBuffer(0, firstBuf.Length + headerLen));
            }
            finally
            {
                sendArrayPool.Return(requestPayload);
            }
        }

        public ValueTask<int> GetRecvBufSizeHint (int preferredSize, CancellationToken cancellationToken = default) => new ValueTask<int>(preferredSize);

        public async ValueTask<int> StartRecv (ArraySegment<byte> outBuf, CancellationToken cancellationToken = default)
        {
            var recvBuf = await inputStream.ReadAsync(outBuf.Array.AsBuffer(outBuf.Offset, outBuf.Count), (uint)outBuf.Count, InputStreamOptions.Partial).AsTask(cancellationToken).ConfigureAwait(false);
            if (recvBuf.Length == 0)
            {
                return 0;
            }
            return (int)recvBuf.Length;
        }

        public async Task StartSend (ChannelReader<byte[]> outboundChan, CancellationToken cancellationToken = default)
        {
            while (await outboundChan.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var packetsToSend = new List<byte[]>();
                while (outboundChan.TryRead(out var segment))
                {
                    packetsToSend.Add(segment);
                }
                var pendingTasks = new Task[packetsToSend.Count];
                for (var index = 0; index < packetsToSend.Count; ++index)
                {
                    var segment = packetsToSend[index];
                    pendingTasks[index] = outputStream.WriteAsync(segment.AsBuffer()).AsTask(cancellationToken);
                }
                await Task.WhenAll(pendingTasks).ConfigureAwait(false);
            }
            await outputStream.FlushAsync().AsTask(cancellationToken).ConfigureAwait(false);
            outputStream.Dispose();
            socket.Dispose();
        }

        public async Task StartRecvPacket (ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            const int RECV_BUFFER_LEN = 2048;
            byte[] buf = new byte[RECV_BUFFER_LEN];
            var stream = inputStream.AsStreamForRead();
            int offset = 0, unconsumedLen = 0;
            while (!cancellationToken.IsCancellationRequested)
            {
                int parseResult = Destination.Destination.TryParseSocks5StyleAddress(buf.AsSpan(offset, unconsumedLen), out _, TransportProtocol.Udp);
                unconsumedLen -= parseResult;
                while (parseResult == 0 || unconsumedLen < 4) // Need more data as address header + len + crlf
                {
                    var readLen = await stream.ReadAsync(buf, offset, RECV_BUFFER_LEN - offset).ConfigureAwait(false);
                    offset += readLen;
                    unconsumedLen += readLen;
                    if (readLen == 0)
                    {
                        goto END;
                    }
                    if (parseResult == 0)
                    {
                        parseResult = Destination.Destination.TryParseSocks5StyleAddress(buf.AsSpan(0, unconsumedLen), out _, TransportProtocol.Udp);
                        unconsumedLen -= parseResult;
                    }
                }

                // buf now contains a valid address header, check payload length and CRLF
                ushort len = (ushort)(buf[parseResult] << 8 | buf[parseResult + 1]);
                if (buf[parseResult + 2] != 0x0D || buf[parseResult + 3] != 0x0A)
                {
                    if (DebugLogger.LogNeeded())
                    {
                        DebugLogger.Log("Received a malformed Trojan UDP response");
                    }
                    break;
                }
                unconsumedLen -= 4;
                while (unconsumedLen < len)
                {
                    var readLen = await stream.ReadAsync(buf, offset, RECV_BUFFER_LEN - offset).ConfigureAwait(false);
                    offset += readLen;
                    unconsumedLen += readLen;
                    if (readLen == 0)
                    {
                        goto END;
                    }
                }
                await localAdapter.WritePacketToLocal(buf.AsSpan(offset - len, len), cancellationToken).ConfigureAwait(false);
                unconsumedLen -= len;
                if (unconsumedLen > 0)
                {
                    Array.Copy(buf, parseResult + len, buf, 0, unconsumedLen);
                }
                offset = unconsumedLen;
            }
        END:
            ;
        }

        public async void SendPacketToRemote (Memory<byte> data, Destination.Destination destination)
        {
            var sendBuf = sendArrayPool.Rent(data.Length + destination.Host.Size + 8);
            try
            {
                var headerLen = FillTrojanRequest(sendBuf, destination, true, (ushort)data.Length);
                data.Span.CopyTo(sendBuf.AsSpan(headerLen));
                await outputStream.WriteAsync(sendBuf.AsBuffer(0, headerLen + data.Length));
            }
            finally
            {
                sendArrayPool.Return(sendBuf);
            }
        }

        public void CheckShutdown ()
        {
            // outboundChan = null;
            try
            {
                inputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            // inputStream = null;
            try
            {
                outputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            // outputStream = null;
            try
            {
                socket?.Dispose();
            }
            catch (ObjectDisposedException) { }
            // socket = null;
        }
    }
}
