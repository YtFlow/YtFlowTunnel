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

        public static int FillAddressHeader (Span<byte> requestPayload, Destination.Destination destination)
        {
            int offset = destination.Host.Size + 3;
            switch (destination.Host)
            {
                case DomainNameHost domainHost:
                    offset++;
                    requestPayload[0] = 0x03;
                    requestPayload[1] = (byte)domainHost.Size;
                    domainHost.CopyTo(requestPayload.Slice(2));
                    break;
                case Ipv4Host ipv4:
                    requestPayload[0] = 0x01;
                    ipv4.CopyTo(requestPayload.Slice(1, 4));
                    break;
                case Ipv6Host ipv6:
                    requestPayload[0] = 0x04;
                    ipv6.CopyTo(requestPayload.Slice(2, 16));
                    break;
            }
            requestPayload[offset - 2] = (byte)(destination.Port >> 8);
            requestPayload[offset - 1] = (byte)(destination.Port & 0xFF);
            return offset;
        }

        public static int ParseAddressHeader (Span<byte> data, out Destination.Destination destination, TransportProtocol transportProtocol)
        {
            if (data.Length < 7)
            {
                destination = default;
                return -1;
            }
            ushort port;
            switch (data[0])
            {
                case 1:
                    var ipBe = BitConverter.ToUInt32(data.Slice(1, 4).ToArray(), 0);
                    port = (ushort)(data[5] << 8 | data[6] & 0xFF);
                    var ipv4Host = new Ipv4Host(ipBe);
                    destination = new Destination.Destination(ipv4Host, port, transportProtocol);
                    return 7;
                case 3:
                    var domainLen = data[1];
                    if (data.Length < domainLen + 4)
                    {
                        destination = default;
                        return -1;
                    }
                    var domainHost = new DomainNameHost(data.Slice(2, domainLen).ToArray());
                    port = (ushort)(data[2 + domainLen] << 8 | data[3 + domainLen] & 0xFF);
                    destination = new Destination.Destination(domainHost, port, transportProtocol);
                    return domainLen + 4;
                case 4:
                    throw new NotImplementedException();
                default:
                    destination = default;
                    return -1;
            }
        }

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
            if (await outboundChan.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out firstBuf);
            }
            int firstBufLen = firstBuf.Length;
            int requestPayloadLen = firstBufLen + destination.Host.Size + 4;
            var requestPayload = sendArrayPool.Rent(requestPayloadLen);
            var headerLen = FillAddressHeader(requestPayload, destination);
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
                client.Client.Dispose();
            }
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

                var headerLen = ParseAddressHeader(outDataBuffer.AsSpan(0, (int)decDataLen), out _, TransportProtocol.Udp);
                if (headerLen <= 0)
                {
                    continue;
                }
                await localAdapter.WriteToLocal(outDataBuffer.AsSpan(headerLen, (int)decDataLen - headerLen), cancellationToken).ConfigureAwait(false);
            }
        }

        public async void SendPacketToRemote (byte[] data, Destination.Destination destination)
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
                var headerLen = FillAddressHeader(udpSendBuffer, destination);
                data.CopyTo(udpSendBuffer.AsSpan(headerLen));
                var cryptor = ShadowsocksFactory.GlobalCryptorFactory.CreateCryptor();
                var ivLen = Encrypt(Array.Empty<byte>(), udpSendEncBuffer, cryptor); // Fill IV/Salt first
                var len = EncryptAll(udpSendBuffer.AsSpan(0, headerLen + data.Length), udpSendEncBuffer.AsSpan((int)ivLen), cryptor);
                _ = udpClient.SendAsync(udpSendEncBuffer, (int)(len + ivLen), server, port).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    udpSendLock?.Release();
                }
                catch (ObjectDisposedException) { }
                sendArrayPool.Return(udpSendBuffer);
                sendArrayPool.Return(udpSendEncBuffer);
            }
        }

        public void CheckShutdown ()
        {
            // cryptor?.Dispose();
            cryptor = null;
            outboundChan = null;
            try
            {
                networkStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            networkStream = null;
            try
            {
                client?.Dispose();
            }
            catch (ObjectDisposedException) { }
            try
            {
                udpSendLock?.Dispose();
            }
            catch (ObjectDisposedException) { }
            client = null;
            udpClient = null;
            localAdapter = null;
        }
    }
}
