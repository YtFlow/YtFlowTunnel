using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Wintun2socks;
using YtCrypto;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    internal sealed class ShadowsocksAdapter : ProxyAdapter
    {
        private const int RECV_BUFFER_LEN = 1024;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork);
        NetworkStream networkStream;
        string server;
        int port;
        private ConcurrentQueue<byte[]> localbuf = new ConcurrentQueue<byte[]>();
        private SemaphoreSlim encLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim decLock = new SemaphoreSlim(1, 1);
        private ICryptor cryptor = null;
        private byte[] decryptBuf = new byte[RECV_BUFFER_LEN];
        private bool remoteConnected = false;

        public (byte[] data, uint len) Encrypt (byte[] data, uint len)
        {
            // await encLock.WaitAsync();
            try
            {
                // Reserve for iv
                var outArr = new byte[len + 16];
                var outLen = cryptor.Encrypt(data, len, outArr);
                return (outArr, outLen);
            }
            finally
            {
                // encLock.Release();
            }
        }

        public Memory<byte> Decrypt (byte[] data, uint len)
        {
            // await decLock.WaitAsync();
            try
            {
                var outLen = cryptor.Decrypt(data, len, decryptBuf);
                return decryptBuf.AsMemory(0, (int)outLen);
            }
            finally
            {
                // decLock.Release();
            }
        }

        public ShadowsocksAdapter (string srv, int port, ICryptor _cryptor, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            server = srv;
            this.port = port;
            cryptor = _cryptor;

            Init();
        }

        public async void Init ()
        {
            try
            {
                await r.ConnectAsync(server, port);
                networkStream = r.GetStream();
            }
            catch (Exception)
            {
                Debug.WriteLine("Error connecting to remote");
                DisconnectRemote();
                Reset();
                return;
            }
            Debug.WriteLine("Connected");
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
            string domain = DnsProxyServer.Lookup((byte)((_socket.RemoteAddr >> 24 | (0x00FF0000 & _socket.RemoteAddr) >> 8)));
            if (domain == null)
            {
                Debug.WriteLine("Cannot find DNS record");
                DisconnectRemote();
                Reset();
                return;
            }
            byte[] firstSeg = null;
            int headerLen = domain.Length + 4;
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
            firstSeg[0] = 0x03;
            firstSeg[1] = (byte)domain.Length;
            Encoding.ASCII.GetBytes(domain).CopyTo(firstSeg, 2);
            firstSeg[headerLen - 2] = (byte)(_socket.RemotePort >> 8);
            firstSeg[headerLen - 1] = (byte)(_socket.RemotePort & 0xFF);
            var (encryptedFirstSeg, encryptedFirstSegLen) = Encrypt(firstSeg, (uint)firstSeg.Length);

            try
            {
                await networkStream.WriteAsync(encryptedFirstSeg, 0, (int)encryptedFirstSegLen);
                while (localbuf.TryDequeue(out var buf))
                {
                    bytesToConfirm += buf.Length;
                    // await networkWriteStream.WriteAsync(await Encrypt(buf));
                    var (data, len) = Encrypt(buf, (uint)buf.Length);
                    await networkStream.WriteAsync(data, 0, (int)len);
                }
                remoteConnected = true;
                Recved((ushort)bytesToConfirm);
                //await networkWriteStream.FlushAsync();
                Debug.WriteLine("Sent data with header");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error sending header to remote");
                DisconnectRemote();
                Reset();
                return;
            }

            // IBuffer remotebuf = WindowsRuntimeBuffer.Create(RECV_BUFFER_LEN);
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

                    await RemoteReceived(Decrypt(remotebuf, (uint)len));
                }
                catch (Exception)
                {
                    break;
                }
            }

            try
            {
                Debug.WriteLine("Remote sent no data");
                // networkReadStream?.Dispose();
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
                        var (data, len) = Encrypt(buf, (uint)buf.Length);
                        await networkStream?.WriteAsync(data, 0, (int)len);
                    }
                    await networkStream?.FlushAsync();
                }
            }
            catch (Exception) { }
            try
            {
                // networkWriteStream?.Dispose();
                r?.Client?.Shutdown(SocketShutdown.Send);
                Debug.WriteLine("Disposed remote write stream");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error closing remote write stream");
            }
            RemoteDisconnected = true;
            CheckShutdown();
            // try
            // {
            //     r.Dispose();
            //     Debug.WriteLine("remote socket disposed");
            // }
            // catch (Exception)
            // {
            //     Debug.WriteLine("remote socket already disposed");
            // }
        }

        protected override async void SendToRemote (byte[] buffer)
        {
            if (remoteConnected)
            {
                try
                {
                    var (data, len) = Encrypt(buffer, (uint)buffer.Length);
                    await networkStream.WriteAsync(data, 0, (int)len);
                    await networkStream.FlushAsync();
                    Recved((ushort)buffer.Length);
#if YTLOG_VERBOSE
                    Debug.WriteLine("Sent data" + buffer.Length);
#endif
                    // r.Send(e);
                }
                catch (Exception)
                {
                    Debug.WriteLine("Cannot send to remote");
                }
            }
            else
            {
                // buffer.CopyTo(0, localbuf, localbuf.Length, buffer.Length);
                // localbuf.Length += buffer.Length;
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
                encLock.Dispose();
                decLock.Dispose();
                // cryptor?.Dispose();
                cryptor = null;
                // networkReadStream?.Dispose();
                networkStream?.Dispose();
                r?.Dispose();
                // r.Client.Dispose();
            }
            base.CheckShutdown();
        }
    }
}
