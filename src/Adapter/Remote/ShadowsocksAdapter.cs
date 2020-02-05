using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtCrypto;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal class ShadowsocksAdapter : IRemoteAdapter
    {
        protected const int RECV_BUFFER_LEN = 4096;
        protected virtual int sendBufferLen => 4096;
        protected readonly string server;
        protected readonly int port;
        protected TcpClient client = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true,
            ReceiveTimeout = 20,
            SendTimeout = 20
        };
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
        /// <returns>The length of <paramref name="outData"/> used.</returns>
        public virtual unsafe uint Encrypt (ReadOnlySpan<byte> data, Span<byte> outData)
        {
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

        public unsafe uint Decrypt (ReadOnlySpan<byte> data, Span<byte> outData)
        {
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
            // No way to pass a cancellationToken in.
            // See https://github.com/dotnet/runtime/issues/921
            this.localAdapter = localAdapter;
            var connectTask = client.ConnectAsync(server, port).ConfigureAwait(false);

            var destination = localAdapter.Destination;
            byte[] firstBuf = Array.Empty<byte>();
            if (await outboundChan.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out firstBuf);
            }
            int firstBufLen = firstBuf.Length;
            byte[] requestPayload;
            switch (destination.Host)
            {
                case DomainNameHost domainHost:
                    requestPayload = new byte[firstBufLen + domainHost.Size + 4];
                    requestPayload[0] = 0x03;
                    requestPayload[1] = (byte)domainHost.Size;
                    domainHost.CopyTo(requestPayload.AsSpan(2));
                    break;
                case Ipv4Host ipv4:
                    requestPayload = new byte[firstBufLen + 7];
                    requestPayload[0] = 0x01;
                    ipv4.CopyTo(requestPayload.AsSpan(1, 4));
                    break;
                default:
                    throw new NotImplementedException("Unimplemented host type: " + destination.Host.ToString());
            }
            requestPayload[requestPayload.Length - firstBufLen - 2] = (byte)(destination.Port >> 8);
            requestPayload[requestPayload.Length - firstBufLen - 1] = (byte)(destination.Port & 0xFF);
            firstBuf.CopyTo(requestPayload.AsSpan(requestPayload.Length - firstBufLen));
            var encryptedFirstSeg = new byte[requestPayload.Length + 66]; // Reserve space for IV or salt + 2 * tag + size
            var ivLen = Encrypt(Array.Empty<byte>(), encryptedFirstSeg); // Fill IV/salt first
            var encryptedFirstSegLen = ivLen + Encrypt(requestPayload, encryptedFirstSeg.AsSpan((int)ivLen));

            await connectTask;
            networkStream = client.GetStream();
            await networkStream.WriteAsync(encryptedFirstSeg, 0, (int)encryptedFirstSegLen).ConfigureAwait(false);
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
            byte[] buf = new byte[sendBufferLen + 34]; // dataLen + 2 * tag + data
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
                var offset = 0;
                while (offset < data.Length)
                {
                    var inDataLen = Math.Min(data.Length - offset, sendBufferLen);
                    var outDataLen = Encrypt(data.AsSpan().Slice(offset, inDataLen), buf);
                    offset += inDataLen;
                    // TODO: batch write
                    await networkStream.WriteAsync(buf, 0, (int)outDataLen, cancellationToken).ConfigureAwait(false);
                }
                // await networkStream.FlushAsync();
                localAdapter.ConfirmRecvFromLocal((ushort)data.Length);
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Send);
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
            client = null;
            localAdapter = null;
        }
    }
}
