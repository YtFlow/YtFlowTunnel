using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Foundation.Metadata;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    /// <summary>
    /// Trojan adapter
    /// </summary>
    /// <remarks>To use Trojan adapter, please manually upgrade minimum SDK version to 16299 or later.</remarks>
    internal sealed class TrojanAdapter : ProxyAdapter
    {
        private const int RECV_BUFFER_LEN = 1024;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork);
        // SslStream networkStream;
        NetworkStream networkStream;
        string server;
        int port;
        private ConcurrentQueue<byte[]> localbuf = new ConcurrentQueue<byte[]>();
        private bool remoteConnected = false;

        public TrojanAdapter (string srv, int port, string hashedPassword, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            if (!ApiInformation.IsApiContractPresent("Windows.Foundation.UniversalApiContract", 5))
            {
                throw new InvalidOperationException("Trojan adapter is not supported on platforms earlier than 1709");
            }
            server = srv;
            this.port = port;
            // TODO: hash password
            if (hashedPassword.Length != 56 || hashedPassword.Any(c => !((c >= 0 && c <= 9) || (c > 'a' && c < 'f'))))
            {
                throw new ArgumentOutOfRangeException("Hashed password only allows 56 hex characters");
            }

            Init(hashedPassword);
        }

        public async void Init (string hashedPassword)
        {
            try
            {
                await r.ConnectAsync(server, port);
                // TODO: verify certificate
                // TODO: compile first
                // networkStream = new SslStream(r.GetStream(), false, new RemoteCertificateValidationCallback((a, b, c, d) => true));
                // await networkStream.AuthenticateAsClientAsync(server);
            }
            catch (Exception)
            {
                Debug.WriteLine("Error connecting to remote");
                DisconnectRemote();
                Reset();
                return;
            }
            Debug.WriteLine("Connected");
            string domain = DnsProxyServer.Lookup(_socket.RemoteAddr);
            if (domain == null)
            {
                Debug.WriteLine("Cannot find DNS record");
                DisconnectRemote();
                Reset();
                return;
            }
            byte[] firstSeg = null;
            int headerLen = domain.Length + 65;
            int bytesToConfirm = 0;
            if (localbuf.TryDequeue(out var firstBuf))
            {
                bytesToConfirm = firstBuf.Length;
                firstSeg = new byte[headerLen + firstBuf.Length];
                Array.Copy(firstBuf, 0, firstSeg, headerLen, firstBuf.Length);
            }
            else
            {
                firstSeg = new byte[headerLen];
            }
            Encoding.UTF8.GetBytes(hashedPassword).CopyTo(firstSeg.AsSpan()); // hex(SHA224(password))
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
            await networkStream.WriteAsync(firstSeg, 0, firstSeg.Length);

            try
            {
                while (localbuf.TryDequeue(out var buf))
                {
                    bytesToConfirm += buf.Length;
                    await networkStream.WriteAsync(buf, 0, buf.Length);
                }
                remoteConnected = true;
                Recved((ushort)bytesToConfirm);
                Debug.WriteLine("Sent data with header");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error sending header to remote");
                DisconnectRemote();
                Reset();
                return;
            }

            byte[] remotebuf = new byte[RECV_BUFFER_LEN];
            while (r.Connected && networkStream.CanRead)
            {
                try
                {
                    var len = await networkStream.ReadAsync(remotebuf, 0, RECV_BUFFER_LEN).ConfigureAwait(false);
                    if (len == 0)
                    {
                        break;
                    }
#if YTLOG_VERBOSE
                    Debug.WriteLine($"Received {len} bytes");
#endif

                    await RemoteReceived(remotebuf.AsMemory(0, len));
                }
                catch (Exception)
                {
                    break;
                }
            }

            try
            {
                Debug.WriteLine("Remote sent no data");
                r?.Client?.Shutdown(SocketShutdown.Receive);
                Close();
            }
            catch (Exception) { }
        }

        protected override async void DisconnectRemote ()
        {
            if (RemoteDisconnecting)
            {
                return;
            }
            RemoteDisconnecting = true;
            try
            {
                if (!localbuf.IsEmpty)
                {
                    while (localbuf.TryDequeue(out var buf))
                    {
                        await networkStream?.WriteAsync(buf, 0, buf.Length);
                    }
                    await networkStream?.FlushAsync();
                }
            }
            catch (Exception) { }
            try
            {
                r?.Client?.Shutdown(SocketShutdown.Send);
                Debug.WriteLine("Disposed remote write stream");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error closing remote write stream");
            }
            RemoteDisconnected = true;
            CheckShutdown();
        }

        protected override async void SendToRemote (byte[] buffer)
        {
            if (remoteConnected)
            {
                try
                {
                    await networkStream.WriteAsync(buffer, 0, buffer.Length);
                    await networkStream.FlushAsync();
                    Recved((ushort)buffer.Length);
#if YTLOG_VERBOSE
                    Debug.WriteLine("Sent data" + buffer.Length);
#endif
                }
                catch (Exception)
                {
                    Debug.WriteLine("Cannot send to remote");
                }
            }
            else
            {
                localbuf.Enqueue(buffer);
#if YTLOG_VERBOSE
                Debug.WriteLine("Queued data" + buffer.Length);
#endif
            }
        }

        protected override void CheckShutdown ()
        {
            if (IsShutdown)
            {
                networkStream?.Dispose();
                r?.Dispose();
            }
            base.CheckShutdown();
        }
    }
}
