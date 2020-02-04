using System;
using System.Collections.Generic;
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
        private readonly HostName server;
        private string port;
        private readonly Memory<byte> hashedPassword;
        private readonly bool allowInsecure;
        private StreamSocket socket = new StreamSocket();
        private IInputStream inputStream;
        private IOutputStream outputStream;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
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
            if (await outboundChan.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out firstBuf);
            }
            int firstBufLen = firstBuf.Length;
            byte[] requestPayload;
            switch (destination.Host)
            {
                case DomainNameHost domainHost:
                    requestPayload = new byte[firstBuf.Length + domainHost.Size + 65];
                    hashedPassword.CopyTo(requestPayload); // hex(SHA224(password))
                    requestPayload[56] = 0x0D; // CR
                    requestPayload[57] = 0x0A; // LF
                    requestPayload[58] = 0x01; //  CMD
                    requestPayload[59] = 0x03; //  ATYP
                    requestPayload[60] = (byte)domainHost.Size;
                    domainHost.CopyTo(requestPayload.AsSpan(61, domainHost.Size));
                    break;
                case Ipv4Host ipv4:
                    requestPayload = new byte[firstBuf.Length + 68];
                    hashedPassword.CopyTo(requestPayload); // hex(SHA224(password))
                    requestPayload[56] = 0x0D; // CR
                    requestPayload[57] = 0x0A; // LF
                    requestPayload[58] = 0x01; //  CMD
                    requestPayload[59] = 0x01; //  ATYP
                    ipv4.CopyTo(requestPayload.AsSpan(60, 4));
                    break;
                default:
                    throw new NotImplementedException("Unimplemented host type: " + destination.Host.ToString());

            }
            requestPayload[requestPayload.Length - firstBufLen - 4] = (byte)(destination.Port >> 8);
            requestPayload[requestPayload.Length - firstBufLen - 3] = (byte)(destination.Port & 0xFF);
            requestPayload[requestPayload.Length - firstBufLen - 2] = 0x0D;
            requestPayload[requestPayload.Length - firstBufLen - 1] = 0x0A;
            firstBuf.CopyTo(requestPayload.AsSpan(requestPayload.Length - firstBufLen, firstBufLen));

            await connectTask;
            inputStream = socket.InputStream;
            outputStream = socket.OutputStream;
            await outputStream.WriteAsync(requestPayload.AsBuffer());
            if (firstBufLen > 0)
            {
                localAdapter.ConfirmRecvFromLocal((ushort)firstBufLen);
            }
        }

        public async Task StartRecv (CancellationToken cancellationToken = default)
        {
            //
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (true)
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
                var packetsToSend = new List<IBuffer>();
                while (outboundChan.Reader.TryRead(out var data))
                {
                    packetsToSend.Add(data.AsBuffer());
                    totalBytes += data.Length;
                }
                var pendingTasks = new Task[packetsToSend.Count];
                for (var index = 0; index < packetsToSend.Count; ++index)
                {
                    pendingTasks[index] = outputStream.WriteAsync(packetsToSend[index]).AsTask(cancellationToken);
                }
                await Task.WhenAll(pendingTasks).ConfigureAwait(false);
                localAdapter.ConfirmRecvFromLocal((ushort)totalBytes);
            }
            await outputStream.FlushAsync().AsTask(cancellationToken).ConfigureAwait(false);
            outputStream.Dispose();
            socket.Dispose();
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

        public void CheckShutdown ()
        {
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
