using System;
using System.Buffers;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtCrypto;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Factory;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal class ShadowsocksAdapter : IRemoteAdapter
    {
        private readonly SemaphoreSlim udpSendLock = new SemaphoreSlim(1, 1);
        private readonly static ArrayPool<byte> sendArrayPool = ArrayPool<byte>.Create();
        private readonly ChannelClosedException noEnoughIvException = new ChannelClosedException("No enough iv received");
        protected const int RECV_BUFFER_LEN = 4096;
        protected virtual int sendBufferLen => 4096;
        protected readonly string server;
        protected readonly int port;
        protected TcpClient client;
        protected UdpClient udpClient;
        protected NetworkStream networkStream;
        protected ILocalAdapter localAdapter;
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

        public ShadowsocksAdapter (string server, int port, ICryptor cryptor)
        {
            this.server = server;
            this.port = port;
            this.cryptor = cryptor;
        }

        public async ValueTask Init (ChannelReader<byte[]> outboundChan, ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;
            var destination = localAdapter.Destination;
            ConfiguredTaskAwaitable connectTask;
            switch (destination.TransportProtocol)
            {
                case TransportProtocol.Tcp:
                    client = new TcpClient(AddressFamily.InterNetwork)
                    {
                        NoDelay = true,
                    };
                    // No way to pass a cancellationToken in.
                    // See https://github.com/dotnet/runtime/issues/921
                    connectTask = client.ConnectAsync(server, port).ConfigureAwait(false);
                    break;
                case TransportProtocol.Udp:
                    cryptor = null;
                    // Shadowsocks does not require a handshake for UDP transport
                    udpClient = new UdpClient();
                    udpClient.Client.Connect(server, port);
                    return;
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
                await connectTask;
                networkStream = client.GetStream();
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
                receiveIvTask = ReceiveIv(requestPayload);
                // TODO: necessary to wait until the first segment being sent?
                await networkStream.WriteAsync(encryptedFirstSeg, 0, (int)encryptedFirstSegLen).ConfigureAwait(false);
            }
            finally
            {
                sendArrayPool.Return(encryptedFirstSeg, true);
            }
            client.NoDelay = false;
        }

        private async Task ReceiveIv (byte[] buf)
        {
            try
            {
                int ivLen = (int)cryptor.IvLen, ivReceived = 0;
                while (ivReceived < ivLen)
                {
                    var chunkLen = await networkStream.ReadAsync(buf, ivReceived, ivLen - ivReceived);
                    if (chunkLen == 0)
                    {
                        throw noEnoughIvException;
                    }
                    ivReceived += chunkLen;
                }
                Decrypt(buf.AsSpan(0, ivLen), Array.Empty<byte>(), cryptor);
            }
            finally
            {
                sendArrayPool.Return(buf);
            }
        }

        public virtual ValueTask<int> GetRecvBufSizeHint (CancellationToken cancellationToken = default) => new ValueTask<int>(RECV_BUFFER_LEN);

        public virtual async ValueTask<int> StartRecv (byte[] outBuf, int offset, CancellationToken cancellationToken = default)
        {
            if (!receiveIvTask.IsCompleted)
            {
                await receiveIvTask.ConfigureAwait(false);
            }
            var len = await networkStream.ReadAsync(outBuf, offset, RECV_BUFFER_LEN, cancellationToken).ConfigureAwait(false);
            if (len == 0)
            {
                return 0;
            }
            return (int)Decrypt(outBuf.AsSpan(offset, len), outBuf.AsSpan(offset));
        }

        public async Task StartSend (ChannelReader<byte[]> outboundChan, CancellationToken cancellationToken = default)
        {
            if (localAdapter.Destination.TransportProtocol == TransportProtocol.Udp)
            {
                return;
            }
            while (await outboundChan.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.TryRead(out var data);
                var offset = 0;
                while (offset < data.Length)
                {
                    var inDataLen = Math.Min(data.Length - offset, sendBufferLen);
                    var buf = sendArrayPool.Rent(inDataLen + 34); // size(2) + sizeTag(16) + data + dataTag(16)
                    try
                    {
                        var outDataLen = Encrypt(data.AsSpan().Slice(offset, inDataLen), buf);
                        offset += inDataLen;
                        // TODO: batch write
                        await networkStream.WriteAsync(buf, 0, (int)outDataLen, cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        sendArrayPool.Return(buf);
                    }
                }
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            client.Dispose();
        }

        public async virtual Task StartRecvPacket (CancellationToken cancellationToken = default)
        {
            var outDataBuffer = new byte[sendBufferLen + 66];
            while (!cancellationToken.IsCancellationRequested && udpClient != null)
            {
                var result = await udpClient.ReceiveAsync().ConfigureAwait(false);
                var cryptor = ShadowsocksFactory.GlobalCryptorFactory.CreateCryptor();
                var decDataLen = Decrypt(result.Buffer, outDataBuffer, cryptor);
                // TODO: support IPv6/domain name address type
                if (decDataLen < 7 || outDataBuffer[0] != 1)
                {
                    continue;
                }

                var headerLen = Destination.Destination.TryParseSocks5StyleAddress(outDataBuffer.AsSpan(0, (int)decDataLen), out _, TransportProtocol.Udp);
                if (headerLen <= 0)
                {
                    continue;
                }
                await localAdapter.WritePacketToLocal(outDataBuffer.AsSpan(headerLen, (int)decDataLen - headerLen), cancellationToken).ConfigureAwait(false);
            }
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
                _ = udpClient.SendAsync(udpSendEncBuffer, (int)(len + ivLen), server, port).ConfigureAwait(false);
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

        public void CheckShutdown ()
        {
            // cryptor?.Dispose();
            // cryptor = null;
            // outboundChan = null;
            try
            {
                networkStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            // networkStream = null;
            try
            {
                client?.Dispose();
            }
            catch (ObjectDisposedException) { }
            try
            {
                udpSendLock.Dispose();
            }
            catch (ObjectDisposedException) { }
            // client = null;
            // udpClient = null;
            localAdapter = null;
        }
    }
}
