using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Networking;
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
        private const int RECV_BUFFER_LEN = 4096;
        private static ArrayPool<byte> sendArrayPool = ArrayPool<byte>.Create();
        private readonly HostName server;
        private string port;
        private readonly Memory<byte> hashedPassword;
        private readonly bool allowInsecure;
        private StreamSocket socket = new StreamSocket();
        private IInputStream inputStream;
        private IOutputStream outputStream;
        private Channel<(byte[] Data, int Size)> outboundChan = Channel.CreateUnbounded<(byte[] Data, int Size)>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });
        private ILocalAdapter localAdapter;
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

        public async Task Init (ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;
            if (allowInsecure)
            {
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.IncompleteChain);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
                socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
            }
            var connectTask = socket.ConnectAsync(server, port, SocketProtectionLevel.Tls12).AsTask().ConfigureAwait(false);
            // TODO: custom certificate, server name

            var destination = localAdapter.Destination;
            byte[] firstBuf = Array.Empty<byte>();
            int firstBufLen = firstBuf.Length;
            var firstBufCancel = new CancellationTokenSource(500);
            try
            {
                if (await outboundChan.Reader.WaitToReadAsync(firstBufCancel.Token).ConfigureAwait(false))
                {
                    outboundChan.Reader.TryRead(out var tuple);
                    firstBuf = tuple.Data;
                    firstBufLen = tuple.Size;
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                firstBufCancel.Dispose();
            }
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
            if (firstBufLen > 0)
            {
                localAdapter.ConfirmRecvFromLocal((ushort)firstBufLen);
            }
        }

        public async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (!cancellationToken.IsCancellationRequested)
            {
                var recvBuf = await inputStream.ReadAsync(buf.AsBuffer(), RECV_BUFFER_LEN, InputStreamOptions.Partial).AsTask(cancellationToken).ConfigureAwait(false);
                if (recvBuf.Length == 0)
                {
                    break;
                }
                await localAdapter.WriteToLocal(buf.AsSpan(0, (int)recvBuf.Length), cancellationToken);
            }
        }

        public async Task StartSend (CancellationToken cancellationToken = default)
        {
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var totalBytes = 0;
                var packetsToSend = new List<(byte[] Data, int Size)>();
                while (outboundChan.Reader.TryRead(out var tuple))
                {
                    packetsToSend.Add(tuple);
                    totalBytes += tuple.Size;
                }
                var pendingTasks = new Task[packetsToSend.Count];
                try
                {
                    for (var index = 0; index < packetsToSend.Count; ++index)
                    {
                        var (data, size) = packetsToSend[index];
                        pendingTasks[index] = outputStream.WriteAsync(data.AsBuffer(0, size)).AsTask(cancellationToken);
                    }
                    await Task.WhenAll(pendingTasks).ConfigureAwait(false);
                }
                finally
                {
                    if (localAdapter.Destination.TransportProtocol == TransportProtocol.Udp)
                    {
                        // The arrays are from our array pool.
                        foreach (var (data, _) in packetsToSend)
                        {
                            sendArrayPool.Return(data);
                        }
                    }
                }
                localAdapter.ConfirmRecvFromLocal((ushort)totalBytes);
            }
            await outputStream.FlushAsync().AsTask(cancellationToken).ConfigureAwait(false);
            outputStream.Dispose();
            socket.Dispose();
        }

        public async void FinishSendToRemote (Exception ex = null)
        {
            outboundChan.Writer.TryComplete(ex);
            if (ex != null && socket != null)
            {
                try
                {
                    await socket.CancelIOAsync().AsTask().ConfigureAwait(false);
                    socket.Dispose();
                }
                catch (ObjectDisposedException) { }
            }
        }

        public async void SendToRemote (byte[] buffer)
        {
            if (outboundChan != null)
            {
                await outboundChan.Writer.WriteAsync((buffer, buffer.Length)).ConfigureAwait(false);
            }
        }

        public async Task StartRecvPacket (CancellationToken cancellationToken = default)
        {
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
                await localAdapter.WriteToLocal(buf.AsSpan(offset - len, len), cancellationToken).ConfigureAwait(false);
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

        public void SendPacketToRemote (byte[] data, Destination.Destination destination)
        {
            if (outboundChan == null)
            {
                return;
            }
            var sendBuf = sendArrayPool.Rent(data.Length + destination.Host.Size + 8);
            // Return the array when it was sent or checking shutdown

            var headerLen = FillTrojanRequest(sendBuf, destination, true, (ushort)data.Length);
            data.CopyTo(sendBuf.AsSpan(headerLen));
            _ = outboundChan.Writer.WriteAsync((sendBuf, headerLen + data.Length));
        }

        public void CheckShutdown ()
        {
            if (outboundChan != null && localAdapter?.Destination.TransportProtocol == TransportProtocol.Udp)
            {
                while (outboundChan.Reader.TryRead(out var tuple))
                {
                    sendArrayPool.Return(tuple.Data);
                }
            }
            outboundChan = null;
            try
            {
                inputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            inputStream = null;
            try
            {
                outputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            outputStream = null;
            try
            {
                socket?.Dispose();
            }
            catch (ObjectDisposedException) { }
            socket = null;
            localAdapter = null;
        }
    }
}
