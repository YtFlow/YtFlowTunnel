using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Wintun2socks;
using YtCrypto;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    internal sealed class RawShadowsocksAdapter : ProxyAdapter
    {
        private const int RECV_BUFFER_LEN = 4096;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork);
        NetworkStream networkStream;
        IInputStream networkReadStream;
        IOutputStream networkWriteStream;
        string server;
        int port;
        private ConcurrentQueue<byte[]> localbuf = new ConcurrentQueue<byte[]>();
        private SemaphoreSlim encLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim decLock = new SemaphoreSlim(1, 1);
        private Test cryptor = null;
        private IBuffer iv = null;
        private bool remoteConnected = false;

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static (byte[] Key, byte[] Iv) EVP_BytesToKey (string password, int keyLen, int ivLen)
        {
            var passwordBytes = CryptographicBuffer.ConvertStringToBinary(password, BinaryStringEncoding.Utf8);
            var m = new List<byte[]>();
            int i = 0;
            var objAlgProv = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmName.MD5.Name);
            var objHash = objAlgProv.CreateHash();
            while (m.Sum(seg => seg.Length) < (keyLen + ivLen))
            {
                IBuffer data = null;
                if (i > 0)
                {
                    var lastBuf = m.Last();
                    data = WindowsRuntimeBuffer.Create(lastBuf.Length + (int)passwordBytes.Length);
                    lastBuf.CopyTo(data);
                    data.Length = (uint)lastBuf.Length;
                }
                else
                {
                    data = WindowsRuntimeBuffer.Create((int)passwordBytes.Length);
                }
                passwordBytes.CopyTo(0, data, data.Length, passwordBytes.Length);
                data.Length += passwordBytes.Length;
                objHash.Append(data);
                m.Add(objHash.GetValueAndReset().ToArray());
                i++;
            }
            var ms = m.SelectMany(seg => seg).ToArray();
            var key = ms.Take(keyLen).ToArray();
            var iv = ms.Skip(keyLen).Take(ivLen).ToArray();
            return (key, iv);
        }

        public async Task<IBuffer> Encrypt (byte[] data)
        {
            await encLock.WaitAsync();
            try
            {
                var outArr = new byte[data.Length];
                var len = cryptor.Encrypt(data, outArr);
                return outArr.AsBuffer(0, (int)len);
            }
            finally
            {
                encLock.Release();
            }
        }

        public async Task<Memory<byte>> Decrypt (byte[] data)
        {
            await decLock.WaitAsync();
            try
            {
                var outArr = new byte[data.Length];
                var len = cryptor.Decrypt(data, outArr);
                return outArr.AsMemory(0, (int)len);
            }
            finally
            {
                decLock.Release();
            }
        }

        public RawShadowsocksAdapter (string srv, int port, string password, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            server = srv;
            this.port = port;
            var (key, _) = EVP_BytesToKey(password, 16, 16);
            iv = CryptographicBuffer.GenerateRandom(16);
            cryptor = new Test(key, iv.ToArray());

            Init();
        }

        public async void Init ()
        {
            try
            {
                await r.ConnectAsync(server, port);
                networkStream = r.GetStream();
                networkReadStream = networkStream.AsInputStream();
                networkWriteStream = networkStream.AsOutputStream();
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
            var header = new byte[domain.Length + 4];
            header[0] = 0x03;
            header[1] = (byte)domain.Length;
            Encoding.ASCII.GetBytes(domain).CopyTo(header, 2);
            header[header.Length - 2] = (byte)(_socket.RemotePort >> 8);
            header[header.Length - 1] = (byte)(_socket.RemotePort & 0xFF);

            try
            {
                await networkWriteStream.WriteAsync(iv);
                await networkWriteStream.WriteAsync(await Encrypt(header));
                int bytesToConfirm = 0;
                while (localbuf.TryDequeue(out var buf))
                {
                    bytesToConfirm += buf.Length;
                    await networkWriteStream.WriteAsync(await Encrypt(buf));
                }
                Recved((ushort)bytesToConfirm);
                //await networkWriteStream.FlushAsync();
                remoteConnected = true;
                Debug.WriteLine("Sent data with header");
            }
            catch (Exception)
            {
                Debug.WriteLine("Error sending header to remote");
                DisconnectRemote();
                Reset();
                return;
            }

            IBuffer remotebuf;
            while (r.Connected)
            {
                try
                {
                    remotebuf = WindowsRuntimeBuffer.Create(RECV_BUFFER_LEN);
                    var res = await networkReadStream.ReadAsync(remotebuf, RECV_BUFFER_LEN, InputStreamOptions.Partial).AsTask().ConfigureAwait(false);
                    var len = res.Length;
                    if (len == 0)
                    {
                        break;
                    }
#if YTLOG_VERBOSE
                    Debug.WriteLine($"Received {len} bytes");
#endif

                    await RemoteReceived(await Decrypt(res.ToArray()));
                }
                catch (Exception)
                {
                    break;
                }
            }

            try
            {
                Debug.WriteLine("Remote sent no data");
                networkReadStream?.Dispose();
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
                        await networkWriteStream?.WriteAsync(await Encrypt(buf));
                    }
                    await networkWriteStream?.FlushAsync();
                }
            }
            catch (Exception) { }
            try
            {
                networkWriteStream?.Dispose();
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
                    await networkWriteStream.WriteAsync(await Encrypt(buffer));
                    await networkWriteStream.FlushAsync();
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
                cryptor?.Dispose();
                networkReadStream.Dispose();
                networkStream.Dispose();
                r.Dispose();
                // r.Client.Dispose();
            }
            base.CheckShutdown();
        }
    }
}
