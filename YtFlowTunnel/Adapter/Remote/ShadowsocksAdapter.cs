using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using YtCrypto;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Factory;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal class ShadowsocksAdapter : IRemoteAdapter
    {
        private readonly static ArrayPool<byte> sendArrayPool = ArrayPool<byte>.Create();
        private readonly static ChannelClosedException noEnoughIvException = new ChannelClosedException("No enough iv received");
        private readonly SemaphoreSlim udpSendLock = new SemaphoreSlim(1, 1);
        private byte[] recvData = null;
        private IBuffer recvDataBuffer = null;
        protected virtual int sendBufferLen => 4096;
        protected readonly string server;
        protected readonly string serviceName;
        protected StreamSocket client;
        protected DatagramSocket udpClient;
        protected Action<DatagramSocket, DatagramSocketMessageReceivedEventArgs> udpReceivedHandler = (_s, _e) => { };
        protected IInputStream tcpInputStream;
        protected IOutputStream udpOutputStream;
        protected ICryptor cryptor = null;
        protected Task receiveIvTask = Task.CompletedTask;

        public bool RemoteDisconnected { get; set; } = false;

        /// <summary>
        /// Encrypt input data using the cryptor. Will be used to send Shadowsocks requests.
        /// </summary>
        /// <param name="data">Input data.</param>
        /// <param name="outData">Output data. Must have enough capacity to hold encrypted data and any additional data.</param>
        /// <param name="cryptor">The cryptor to used. A null value indicates that the connection-wide cryptor should be used.</param>
        /// <returns>The length of <paramref name="outData"/> used.</returns>
        public virtual unsafe uint Encrypt (ReadOnlySpan<byte> data, Span<byte> outData, ICryptor cryptor = null)
        {
            if (cryptor == null)
            {
                cryptor = this.cryptor;
            }
            fixed (byte* dataPtr = &data.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
                // Reserve for iv
                var outLen = cryptor.Encrypt((ulong)dataPtr, (uint)data.Length, (ulong)outDataPtr, (uint)outData.Length);
#pragma warning disable IDE0004
                return (uint)outLen;
#pragma warning restore IDE0004
            }
        }

        public virtual uint EncryptAll (ReadOnlySpan<byte> data, Span<byte> outData, ICryptor cryptor = null)
        {
            return Encrypt(data, outData, cryptor);
        }

        public unsafe virtual uint Decrypt (ReadOnlySpan<byte> data, Span<byte> outData, ICryptor cryptor = null)
        {
            if (cryptor == null)
            {
                cryptor = this.cryptor;
            }
            fixed (byte* dataPtr = &data.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
                var outLen = cryptor.Decrypt((ulong)dataPtr, (uint)data.Length, (ulong)outDataPtr, (uint)outData.Length);
#pragma warning disable IDE0004
                return (uint)outLen;
#pragma warning restore IDE0004
            }
        }

        public ShadowsocksAdapter (string server, string serviceName, ICryptor cryptor)
        {
            this.server = server;
            this.serviceName = serviceName;
            this.cryptor = cryptor;
        }

        public async ValueTask Init (ChannelReader<byte[]> outboundChan, ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            var destination = localAdapter.Destination;
            IAsyncAction connectTask;
            var dev = NetworkInformation.GetInternetConnectionProfile().NetworkAdapter;
            switch (destination.TransportProtocol)
            {
                case TransportProtocol.Tcp:
                    client = new StreamSocket();
                    client.Control.NoDelay = true;
                    connectTask = client.ConnectAsync(new HostName(server), serviceName, SocketProtectionLevel.PlainSocket, dev);
                    tcpInputStream = client.InputStream;
                    break;
                case TransportProtocol.Udp:
                    cryptor = null;
                    // Shadowsocks does not require a handshake for UDP transport
                    udpClient = new DatagramSocket();
                    // MessageReceived must be subscribed at this point
                    udpClient.MessageReceived += UdpClient_MessageReceived;
                    await udpClient.BindServiceNameAsync(string.Empty, dev).AsTask(cancellationToken).ConfigureAwait(false);
                    udpOutputStream = await udpClient.GetOutputStreamAsync(new HostName(server), serviceName).AsTask(cancellationToken).ConfigureAwait(false);
                    return;
                default:
                    throw new NotImplementedException("Unknown transport protocol");
            }

            byte[] firstBuf = Array.Empty<byte>();
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
            int requestPayloadLen = firstBufLen + destination.Host.Size + 4;
            // Later will be reused to store dec iv
            var requestPayload = sendArrayPool.Rent(Math.Max(requestPayloadLen, (int)cryptor.IvLen));
            var headerLen = destination.FillSocks5StyleAddress(requestPayload);
            firstBuf.CopyTo(requestPayload.AsSpan(headerLen));
            var encryptedFirstSeg = sendArrayPool.Rent(requestPayloadLen + 66); // Reserve space for IV or salt + 2 * tag + size
            var ivLen = Encrypt(Array.Empty<byte>(), encryptedFirstSeg); // Fill IV/salt first
            var encryptedFirstSegLen = ivLen + Encrypt(requestPayload.AsSpan(0, headerLen + firstBufLen), encryptedFirstSeg.AsSpan((int)ivLen));

            try
            {
                await connectTask.AsTask(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                sendArrayPool.Return(requestPayload);
                sendArrayPool.Return(encryptedFirstSeg, true);
                throw;
            }
            try
            {
                // Recv iv first, then GetRecvBufSizeHint will not bother with iv stuff
                receiveIvTask = ReceiveIv(requestPayload, cancellationToken);
                _ = client.OutputStream.WriteAsync(encryptedFirstSeg.AsBuffer(0, (int)encryptedFirstSegLen)).AsTask(cancellationToken);
            }
            finally
            {
                sendArrayPool.Return(encryptedFirstSeg, true);
            }
        }

        private async Task ReceiveIv (byte[] buf, CancellationToken cancellationToken)
        {
            try
            {
                uint ivLen = (uint)cryptor.IvLen, ivReceived = 0;
                while (ivReceived < ivLen)
                {
                    var readLen = ivLen - ivReceived;
                    var chunk = await tcpInputStream.ReadAsync(buf.AsBuffer((int)ivReceived, (int)readLen), readLen, InputStreamOptions.Partial).AsTask(cancellationToken).ConfigureAwait(false);
                    if (chunk.Length == 0)
                    {
                        throw noEnoughIvException;
                    }
                    ivReceived += chunk.Length;
                }
                Decrypt(buf.AsSpan(0, (int)ivLen), Array.Empty<byte>(), cryptor);
            }
            finally
            {
                sendArrayPool.Return(buf);
            }
        }

        public virtual ValueTask<int> GetRecvBufSizeHint (int preferredSize, CancellationToken cancellationToken = default) => new ValueTask<int>(preferredSize);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        unsafe int DecryptBuffer (IBuffer buf, Span<byte> outBuf)
        {
            var len = (int)buf.Length;
            if (len == 0)
            {
                return 0;
            }

            if (buf != recvDataBuffer)
            {
                buf.CopyTo(0, recvDataBuffer, 0, (uint)len);
            }
            return (int)Decrypt(recvData.AsSpan(0, len), outBuf.Slice(0, len));
        }

        public virtual async ValueTask<int> StartRecv (ArraySegment<byte> outBuf, CancellationToken cancellationToken = default)
        {
            if (!receiveIvTask.IsCompleted)
            {
                await receiveIvTask.ConfigureAwait(false);
            }
            if (recvData == null)
            {
                recvData = new byte[outBuf.Count];
                recvDataBuffer = recvData.AsBuffer();
            }
            else if (recvData.Length < outBuf.Count)
            {
                ZeroMemory(recvData);
                Array.Resize(ref recvData, outBuf.Count);
                recvDataBuffer = recvData.AsBuffer();
            }
            // The underlying Mbed TLS does not allow in-place stream decryption with an unpadded chunk.
            // A buffer is used to hold the received, encrypted data. No more copies are introduced.
            var chunk = await tcpInputStream.ReadAsync(recvDataBuffer, (uint)outBuf.Count, InputStreamOptions.Partial)
                .AsTask(cancellationToken).ConfigureAwait(false);
            return DecryptBuffer(chunk, outBuf.AsSpan());
        }

        public async Task StartSend (ChannelReader<byte[]> outboundChan, CancellationToken cancellationToken = default)
        {
            if (client == null) // UDP
            {
                return;
            }
            var stream = client.OutputStream;
            while (await outboundChan.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (!outboundChan.TryRead(out var data))
                {
                    continue;
                }
                var offset = 0;
                while (offset < data.Length)
                {
                    var inDataLen = Math.Min(data.Length - offset, sendBufferLen);
                    var buf = sendArrayPool.Rent(inDataLen + 34); // size(2) + sizeTag(16) + data + dataTag(16)
                    try
                    {
                        var outDataLen = (int)Encrypt(data.AsSpan().Slice(offset, inDataLen), buf);
                        offset += inDataLen;
                        // TODO: batch write
                        await stream.WriteAsync(buf.AsBuffer(0, outDataLen)).AsTask(cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        sendArrayPool.Return(buf);
                    }
                }
            }
            await stream.FlushAsync().AsTask(cancellationToken).ConfigureAwait(false);
            // client.Dispose();
        }

        private void UdpClient_MessageReceived (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            udpReceivedHandler(sender, args);
        }

        public unsafe virtual Task StartRecvPacket (ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            var outDataBuffer = new byte[sendBufferLen + 66];
            var tcs = new TaskCompletionSource<object>();
            void packetHandler (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs e)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                try
                {
                    var buffer = e.GetDataReader().DetachBuffer();
                    var ptr = ((IBufferByteAccess)buffer).GetBuffer().ToPointer();
                    var cryptor = ShadowsocksFactory.GlobalCryptorFactory.CreateCryptor();
                    var decDataLen = Decrypt(new ReadOnlySpan<byte>(ptr, (int)buffer.Length), outDataBuffer, cryptor);
                    // TODO: support IPv6/domain name address type
                    if (decDataLen < 7 || outDataBuffer[0] != 1)
                    {
                        return;
                    }

                    var headerLen = Destination.Destination.TryParseSocks5StyleAddress(outDataBuffer.AsSpan(0, (int)decDataLen), out _, TransportProtocol.Udp);
                    if (headerLen <= 0)
                    {
                        return;
                    }
                    localAdapter.WritePacketToLocal(outDataBuffer.AsSpan(headerLen, (int)decDataLen - headerLen), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }
            udpReceivedHandler = packetHandler;
            cancellationToken.Register(() =>
            {
                tcs.TrySetCanceled();
                var socket = udpClient;
                if (socket != null)
                {
                    socket.MessageReceived -= packetHandler;
                }
            });
            return tcs.Task;
        }

        public async void SendPacketToRemote (Memory<byte> data, Destination.Destination destination)
        {
            try
            {
                await udpSendLock.WaitAsync().ConfigureAwait(false);
            }
            catch (NullReferenceException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            var udpSendBuffer = sendArrayPool.Rent(destination.Host.Size + data.Length + 4);
            var udpSendEncBuffer = sendArrayPool.Rent(destination.Host.Size + data.Length + 52);
            try
            {
                // TODO: avoid copy
                var headerLen = destination.FillSocks5StyleAddress(udpSendBuffer);
                data.Span.CopyTo(udpSendBuffer.AsSpan(headerLen));
                var cryptor = ShadowsocksFactory.GlobalCryptorFactory.CreateCryptor();
                var ivLen = Encrypt(Array.Empty<byte>(), udpSendEncBuffer, cryptor); // Fill IV/Salt first
                var len = EncryptAll(udpSendBuffer.AsSpan(0, headerLen + data.Length), udpSendEncBuffer.AsSpan((int)ivLen), cryptor);
                _ = udpOutputStream.WriteAsync(udpSendEncBuffer.AsBuffer(0, (int)(len + ivLen)));
            }
            finally
            {
                try
                {
                    udpSendLock.Release();
                }
                catch (ObjectDisposedException) { }
                sendArrayPool.Return(udpSendBuffer);
                sendArrayPool.Return(udpSendEncBuffer);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroMemory (Span<byte> buffer)
        {
            buffer.Clear();
        }

        public void CheckShutdown ()
        {
            // cryptor?.Dispose();
            // cryptor = null;
            // outboundChan = null;
            if (recvData != null)
            {
                ZeroMemory(recvData);
            }
            if (udpClient != null)
            {
                udpClient.MessageReceived -= UdpClient_MessageReceived;
            }
            try
            {
                tcpInputStream?.Dispose();
                udpOutputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            // networkStream = null;
            try
            {
                client?.Dispose();
                udpClient?.Dispose();
            }
            catch (ObjectDisposedException) { }
            try
            {
                udpSendLock.Dispose();
            }
            catch (ObjectDisposedException) { }
            // client = null;
            // udpClient = null;
        }
    }
}
