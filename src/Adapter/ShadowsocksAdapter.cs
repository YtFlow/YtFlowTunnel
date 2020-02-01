using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Wintun2socks;
using YtCrypto;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    internal sealed class ShadowsocksAdapter : ProxyAdapter
    {
        private const int RECV_BUFFER_LEN = 4096;
        private const int SEND_BUFFER_LEN = 4096;
        TcpClient r = new TcpClient(AddressFamily.InterNetwork)
        {
            NoDelay = true,
            ReceiveTimeout = 20,
            SendTimeout = 20
        };
        NetworkStream networkStream;
        string server;
        int port;
        private Channel<byte[]> outboundChan = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions()
        {
            SingleReader = true
        });
        private ICryptor cryptor = null;

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

        public ShadowsocksAdapter (string srv, int port, ICryptor _cryptor, TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            server = srv;
            this.port = port;
            cryptor = _cryptor;

            Init();
        }

        public async void Init ()
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
                await r.ConnectAsync(server, port).ConfigureAwait(false);
                DebugLogger.Log("Connected: " + domain);
            }
            catch (Exception ex)
            {
                RemoteDisconnected = true;
                DebugLogger.Log("Cannot connect to remote: " + ex.ToString());
                Reset();
                CheckShutdown();
                return;
            }
            int headerLen = domain.Length + 4;
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
            firstSeg[0] = 0x03;
            firstSeg[1] = (byte)domain.Length;
            Encoding.ASCII.GetBytes(domain).CopyTo(firstSeg, 2);
            firstSeg[headerLen - 2] = (byte)(_socket.RemotePort >> 8);
            firstSeg[headerLen - 1] = (byte)(_socket.RemotePort & 0xFF);
            var encryptedFirstSeg = new byte[firstSeg.Length + 16]; // Reserve space for IV
            var encryptedFirstSegLen = Encrypt(firstSeg, encryptedFirstSeg);

            try
            {
                networkStream = r.GetStream();
                await networkStream.WriteAsync(encryptedFirstSeg, 0, (int)encryptedFirstSegLen).ConfigureAwait(false);
                if (bytesToConfirm > 0)
                {
                    Recved((ushort)bytesToConfirm);
                }
                //await networkWriteStream.FlushAsync();

                // Start forwarding data
                var recvCancel = new CancellationTokenSource();
                var sendCancel = new CancellationTokenSource();
                try
                {
                    await Task.WhenAll(
                        StartRecv(recvCancel.Token).ContinueWith(t =>
                        {
                            if (t.IsFaulted)
                            {
                                sendCancel.Cancel();
                                var ex = t.Exception.Flatten().GetBaseException();
                                DebugLogger.Log($"Recv error: {domain}: {ex}");
                                throw ex;
                            }
                        }, recvCancel.Token),
                        StartSend(sendCancel.Token).ContinueWith(t =>
                        {
                            if (t.IsFaulted)
                            {
                                recvCancel.Cancel();
                                var ex = t.Exception.Flatten().GetBaseException();
                                DebugLogger.Log($"Send error: {domain}: {ex}");
                                throw ex;
                            }
                        }, sendCancel.Token)
                    ).ConfigureAwait(false);
                    DebugLogger.Log("Close!: " + domain);
                    await Close().ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Something wrong happened during recv/send and was handled separatedly.
                    DebugLogger.Log("Reset!: " + domain);
                    Reset();
                }
                finally
                {
                    recvCancel.Dispose();
                    sendCancel.Dispose();
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"Error sending header to remote, reset!: {domain} : {ex}");
                Reset();
            }
            finally
            {
                RemoteDisconnected = true;
            }

            try
            {
                CheckShutdown();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"Error shutting down: {domain}: {ex}");
            }
        }

        private async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] remotebuf = new byte[RECV_BUFFER_LEN];
            var networkStream = r.GetStream();
            while (r.Connected && networkStream.CanRead == true)
            {
                var len = await networkStream.ReadAsync(remotebuf, 0, RECV_BUFFER_LEN, cancellationToken).ConfigureAwait(false);
                if (len == 0)
                {
                    break;
                }
                var outLen = Decrypt(remotebuf.AsSpan(0, len), GetSpanForWrite(len));
                await Flush((int)outLen).ConfigureAwait(false);
            }
            await FinishRecv().ConfigureAwait(false);
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

        private async Task StartSend (CancellationToken cancellationToken)
        {
            byte[] decBuf = new byte[SEND_BUFFER_LEN];
            while (await outboundChan.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                outboundChan.Reader.TryRead(out var data);
                var offset = 0;
                while (offset < data.Length)
                {
                    var len = Encrypt(data.AsSpan().Slice(offset, Math.Min(data.Length - offset, SEND_BUFFER_LEN)), decBuf);
                    offset += (int)len;
                    await networkStream.WriteAsync(decBuf, 0, (int)len, cancellationToken).ConfigureAwait(false);
                }
                // await networkStream.FlushAsync();
                Recved((ushort)data.Length);
#if YTLOG_VERBOSE
                Debug.WriteLine("Sent data" + buffer.Length);
#endif
            }
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            r.Client.Shutdown(SocketShutdown.Send);
        }

        protected override void CheckShutdown ()
        {
            // cryptor?.Dispose();
            cryptor = null;
            outboundChan = null;
            try
            {
                networkStream?.Dispose();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                networkStream = null;
            }
            try
            {
                r?.Dispose();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                r = null;
            }
            base.CheckShutdown();
        }
    }
}
