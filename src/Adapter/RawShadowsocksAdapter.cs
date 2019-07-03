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
        private const int RECV_BUFFER_LEN = 1024;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork);
        NetworkStream networkStream;
        // IInputStream networkReadStream;
        // IOutputStream networkWriteStream;
        string server;
        int port;
        private ConcurrentQueue<byte[]> localbuf = new ConcurrentQueue<byte[]>();
        private SemaphoreSlim encLock = new SemaphoreSlim(1, 1);
        private SemaphoreSlim decLock = new SemaphoreSlim(1, 1);
        private Test cryptor = null;
        private byte[] iv = null;
        private byte[] decryptBuf = new byte[RECV_BUFFER_LEN];
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

        public async Task<(byte[] data, uint len)> Encrypt (byte[] data, uint len)
        {
            await encLock.WaitAsync();
            try
            {
                var outArr = new byte[len];
                var outLen = cryptor.Encrypt(data, len, outArr);
                return (outArr, outLen);
            }
            finally
            {
                encLock.Release();
            }
        }

        public async Task<Memory<byte>> Decrypt (byte[] data, uint len)
        {
            await decLock.WaitAsync();
            try
            {
                var outLen = cryptor.Decrypt(data, len, decryptBuf);
                return decryptBuf.AsMemory(0, (int)outLen);
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
            iv = CryptographicBuffer.GenerateRandom(16).ToArray();
            cryptor = new Test(key, iv);

            Init();
        }

        public async void Init ()
        {
            try
            {
                await r.ConnectAsync(server, port);
                networkStream = r.GetStream();
                // networkReadStream = networkStream.AsInputStream();
                // networkWriteStream = networkStream.AsOutputStream();
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
            var (encryptedFirstSeg, encryptedFirstSegLen) = await Encrypt(firstSeg, (uint)firstSeg.Length);
            var dataToSend = new byte[encryptedFirstSegLen + iv.Length];
            Array.Copy(iv, dataToSend, iv.Length);
            Array.Copy(encryptedFirstSeg, 0, dataToSend, iv.Length, (int)encryptedFirstSegLen);

            try
            {
                // await networkWriteStream.WriteAsync(iv);
                // await networkWriteStream.WriteAsync(await Encrypt(header));
                await networkStream.WriteAsync(dataToSend, 0, dataToSend.Length);
                while (localbuf.TryDequeue(out var buf))
                {
                    bytesToConfirm += buf.Length;
                    // await networkWriteStream.WriteAsync(await Encrypt(buf));
                    var (data, len) = await Encrypt(buf, (uint)buf.Length);
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

                    await RemoteReceived(await Decrypt(remotebuf, (uint)len));
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
                        var (data, len) = await Encrypt(buf, (uint)buf.Length);
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
                    var (data, len) = await Encrypt(buffer, (uint)buffer.Length);
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
                cryptor?.Dispose();
                // networkReadStream?.Dispose();
                networkStream?.Dispose();
                r?.Dispose();
                // r.Client.Dispose();
            }
            base.CheckShutdown();
        }
    }
}
