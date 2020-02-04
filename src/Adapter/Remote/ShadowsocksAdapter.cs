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
    internal sealed class ShadowsocksAdapter : IRemoteAdapter
    {
        private const int RECV_BUFFER_LEN = 4096;
        private const int SEND_BUFFER_LEN = 4096;
        private readonly string server;
        private readonly int port;
        private TcpClient client = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true,
            ReceiveTimeout = 20,
            SendTimeout = 20
        };
        private NetworkStream networkStream;
        private ILocalAdapter localAdapter;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });
        private ICryptor cryptor = null;
        public bool RemoteDisconnected { get; set; } = false;

        public unsafe uint Encrypt (ReadOnlySpan<byte> data, Span<byte> outData)
        {
            fixed (byte* dataPtr = &data.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
                // Reserve for iv
#if X64
                var outLen = cryptor.Encrypt((long)dataPtr, (ulong)data.Length, (long)outDataPtr, (ulong)outData.Length);
#else
                var outLen = cryptor.Encrypt((int)dataPtr, (uint)data.Length, (int)outDataPtr, (uint)outData.Length);
#endif
                return (uint)outLen;
            }
        }

        public unsafe uint Decrypt (Span<byte> data, Span<byte> outData)
        {
            fixed (byte* dataPtr = &data.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
#if X64
                var outLen = cryptor.Decrypt((long)dataPtr, (ulong)data.Length, (long)outDataPtr, (ulong)outData.Length);
#else
                var outLen = cryptor.Decrypt((int)dataPtr, (uint)data.Length, (int)outDataPtr, (uint)outData.Length);
#endif
                return (uint)outLen;
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
            /*
            var header = new byte[7];
            header[0] = 0x01;
            header[1] = (byte)(_socket.RemoteAddr & 0xFF);
            header[2] = (byte)(_socket.RemoteAddr >> 8 & 0xFF);
            header[3] = (byte)(_socket.RemoteAddr >> 16 & 0xFF);
            header[4] = (byte)(_socket.RemoteAddr >> 24);
            header[5] = (byte)(_socket.RemotePort >> 8);
            header[6] = (byte)(_socket.RemotePort & 0xFF);
            */

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
                    requestPayload = new byte[firstBuf.Length + domainHost.Size + 4];
                    requestPayload[0] = 0x03;
                    requestPayload[1] = (byte)domainHost.Size;
                    domainHost.CopyTo(requestPayload.AsSpan(2));
                    break;
                default:
                    throw new NotImplementedException("Unimplemented host type: " + destination.Host.ToString());
            }
            requestPayload[requestPayload.Length - firstBufLen - 2] = (byte)(destination.Port >> 8);
            requestPayload[requestPayload.Length - firstBufLen - 1] = (byte)(destination.Port & 0xFF);
            firstBuf.CopyTo(requestPayload.AsSpan(requestPayload.Length - firstBufLen));
            var encryptedFirstSeg = new byte[requestPayload.Length + 16]; // Reserve space for IV
            var encryptedFirstSegLen = Encrypt(requestPayload, encryptedFirstSeg);

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

        public async Task StartSend (CancellationToken cancellationToken)
        {
            byte[] buf = new byte[SEND_BUFFER_LEN];
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
                var offset = 0;
                while (offset < data.Length)
                {
                    var len = Encrypt(data.AsSpan().Slice(offset, Math.Min(data.Length - offset, SEND_BUFFER_LEN)), buf);
                    offset += (int)len;
                    // TODO: batch write
                    await networkStream.WriteAsync(buf, 0, (int)len, cancellationToken).ConfigureAwait(false);
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
