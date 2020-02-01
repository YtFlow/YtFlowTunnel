using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage.Streams;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    /// <summary>
    /// Trojan adapter
    /// </summary>
    internal sealed class TrojanAdapter : ProxyAdapter
    {
        private const int RECV_BUFFER_LEN = 4096;
        private const int SEND_BUFFER_LEN = 4096;
        private StreamSocket socket = new StreamSocket();
        private IInputStream inputStream;
        private IOutputStream outputStream;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });

        public TrojanAdapter (HostName server, string port, Memory<byte> hashedPassword, bool allowInsecure, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            Init(server, port, hashedPassword, allowInsecure);
        }

        public async void Init (HostName server, string port, Memory<byte> hashedPassword, bool allowInsecure)
        {
            string domain = DnsProxyServer.Lookup(_socket.RemoteAddr);
            if (domain == null)
            {
                RemoteDisconnected = true;
                DebugLogger.Log("Cannot find DNS record: " + _socket.RemoteAddr);
                Reset();
                CheckShutdown();
                return;
            }

            try
            {
                socket.Control.NoDelay = true;
                if (allowInsecure)
                {
                    socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Untrusted);
                    socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.WrongUsage);
                    socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.IncompleteChain);
                    socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.Expired);
                    socket.Control.IgnorableServerCertificateErrors.Add(ChainValidationResult.InvalidName);
                }
                await socket.ConnectAsync(server, port, SocketProtectionLevel.Tls12);
                // TODO: custom certificate, server name
            }
            catch (Exception ex)
            {
                RemoteDisconnected = true;
                DebugLogger.Log("Cannot connect to remote: " + ex.ToString());
                Reset();
                CheckShutdown();
                return;
            }

            int headerLen = domain.Length + 65;
            int bytesToConfirm = 0;
            byte[] firstSeg;
            if (outboundChan.Reader.TryRead(out var firstBuf))
            {
                bytesToConfirm = firstBuf.Length;
                firstSeg = new byte[headerLen + firstBuf.Length];
                Array.Copy(firstBuf, 0, firstSeg, headerLen, firstBuf.Length);
            }
            else
            {
                firstSeg = new byte[headerLen];
            }
            hashedPassword.CopyTo(firstSeg); // hex(SHA224(password))
            firstSeg[56] = 0x0D; // CR
            firstSeg[57] = 0x0A; // LF
            firstSeg[58] = 0x01; //  CMD
            firstSeg[59] = 0x03; //  ATYP
            firstSeg[60] = (byte)domain.Length; // DST.ADDR length
            Encoding.ASCII.GetBytes(domain).CopyTo(firstSeg, 61);
            firstSeg[headerLen - 4] = (byte)(_socket.RemotePort >> 8);
            firstSeg[headerLen - 3] = (byte)(_socket.RemotePort & 0xFF);
            firstSeg[headerLen - 2] = 0x0D;
            firstSeg[headerLen - 1] = 0x0A;

            bool headerSent = true;
            try
            {
                inputStream = socket.InputStream;
                outputStream = socket.OutputStream;
                await outputStream.WriteAsync(firstSeg.AsBuffer());
                if (bytesToConfirm > 0)
                {
                    ConfirmRecvFromLocal((ushort)bytesToConfirm);
                }
                headerSent = true;
            }
            catch (Exception ex)
            {
                RemoteDisconnected = true;
                DebugLogger.Log($"Error sending header to remote, reset!: {domain} : {ex}");
                Reset();
                CheckShutdown();
            }

            if (!headerSent)
            {
                return;
            }

            await StartForward(domain);
        }

        protected override async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] buf = new byte[RECV_BUFFER_LEN];
            while (true)
            {
                var recvBuf = await inputStream.ReadAsync(buf.AsBuffer(), RECV_BUFFER_LEN, InputStreamOptions.Partial).AsTask(cancellationToken).ConfigureAwait(false);
                if (recvBuf.Length == 0)
                {
                    break;
                }
                await WriteToLocal(buf.AsSpan(0, (int)recvBuf.Length));
            }
            await FinishInbound().ConfigureAwait(false);
        }

        protected override async Task StartSend (CancellationToken cancellationToken = default)
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
                ConfirmRecvFromLocal((ushort)totalBytes);
            }
            outputStream.Dispose();
        }

        protected override void FinishSendToRemote (Exception ex = null)
        {
            outboundChan.Writer.TryComplete(ex);
        }

        protected override async void SendToRemote (byte[] buffer)
        {
            if (outboundChan != null)
            {
                await outboundChan.Writer.WriteAsync(buffer).ConfigureAwait(false);
            }
        }

        protected override void CheckShutdown ()
        {
            outboundChan = null;
            try
            {
                inputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                inputStream = null;
            }
            try
            {
                outputStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                outputStream = null;
            }
            try
            {
                socket?.Dispose();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                socket = null;
            }
            base.CheckShutdown();
        }

    }
}
