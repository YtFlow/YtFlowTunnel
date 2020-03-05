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
        protected const int RECV_BUFFER_LEN = 4096;
        protected virtual int sendBufferLen => 4096;
        protected readonly string server;
        protected readonly int port;
        protected TcpClient client;
        protected UdpClient udpClient;
        protected NetworkStream networkStream;
        protected ILocalAdapter localAdapter;
        protected Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });
        protected ICryptor cryptor = null;
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
#if X64
                var outLen = cryptor.Encrypt((long)dataPtr, (ulong)data.Length, (long)outDataPtr, (ulong)outData.Length);
#else
                var outLen = cryptor.Encrypt((int)dataPtr, (uint)data.Length, (int)outDataPtr, (uint)outData.Length);
#endif
#pragma warning disable IDE0004
                return (uint)outLen;
#pragma warning restore IDE0004
            }
        }

        public virtual uint EncryptAll (ReadOnlySpan<byte> data, Span<byte> outData, ICryptor cryptor = null)
        {
            return Encrypt(data, outData, cryptor);
        }

        public unsafe uint Decrypt (ReadOnlySpan<byte> data, Span<byte> outData, ICryptor cryptor = null)
        {
            if (cryptor == null)
            {
                cryptor = this.cryptor;
            }
            fixed (byte* dataPtr = &data.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
#if X64
                var outLen = cryptor.Decrypt((long)dataPtr, (ulong)data.Length, (long)outDataPtr, (ulong)outData.Length);
#else
                var outLen = cryptor.Decrypt((int)dataPtr, (uint)data.Length, (int)outDataPtr, (uint)outData.Length);
#endif
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

        public async Task Init (ILocalAdapter localAdapter)
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
                if (await outboundChan.Reader.WaitToReadAsync(firstBufCancel.Token).ConfigureAwait(false))
                {
                    outboundChan.Reader.TryRead(out firstBuf);
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                firstBufCancel.Dispose();
            }
            int firstBufLen = firstBuf.Length;
            int requestPayloadLen = firstBufLen + destination.Host.Size + 4;
            var requestPayload = sendArrayPool.Rent(requestPayloadLen);
            var headerLen = destination.FillSocks5StyleAddress(requestPayload);
            firstBuf.CopyTo(requestPayload.AsSpan(headerLen));
            var encryptedFirstSeg = sendArrayPool.Rent(requestPayloadLen + 66); // Reserve space for IV or salt + 2 * tag + size
            var ivLen = Encrypt(Array.Empty<byte>(), encryptedFirstSeg); // Fill IV/salt first
            var encryptedFirstSegLen = ivLen + Encrypt(requestPayload.AsSpan(0, headerLen + firstBufLen), encryptedFirstSeg.AsSpan((int)ivLen));
            sendArrayPool.Return(requestPayload);

            try
            {
                await connectTask;
                networkStream = client.GetStream();
                await networkStream.WriteAsync(encryptedFirstSeg, 0, (int)encryptedFirstSegLen).ConfigureAwait(false);
            }
            finally
            {
                sendArrayPool.Return(encryptedFirstSeg, true);
            }
            if (firstBufLen > 0)
            {
                localAdapter.ConfirmRecvFromLocal((ushort)firstBufLen);
            }
            client.NoDelay = false;
            //await networkWriteStream.FlushAsync();
        }

        public virtual async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (client.Connected && networkStream.CanRead)
            {
                var len = await networkStream.ReadAsync(buf, 0, RECV_BUFFER_LEN, cancellationToken).ConfigureAwait(false);
                if (len == 0)
                {
                    break;
                }
                uint outLen = Decrypt(buf.AsSpan(0, len), localAdapter.GetSpanForWriteToLocal(len));
                await localAdapter.FlushToLocal((int)outLen, cancellationToken).ConfigureAwait(false);
            }
        }

        public void FinishSendToRemote (Exception ex = null)
        {
            outboundChan.Writer.TryComplete(ex);
            if (ex != null)
            {
                try
                {
                    client?.Client.Dispose();
                }
                catch (ObjectDisposedException) { }
            }
        }

        public void SendToRemote (byte[] buffer)
        {
            if (outboundChan != null)
            {
                _ = outboundChan.Writer.WriteAsync(buffer);
            }
        }

        public async Task StartSend (CancellationToken cancellationToken = default)
        {
            if (localAdapter.Destination.TransportProtocol == TransportProtocol.Udp)
            {
                return;
            }
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
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
                // await networkStream.FlushAsync();
                localAdapter.ConfirmRecvFromLocal((ushort)data.Length);
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
                await localAdapter.WriteToLocal(outDataBuffer.AsSpan(headerLen, (int)decDataLen - headerLen), cancellationToken).ConfigureAwait(false);
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
