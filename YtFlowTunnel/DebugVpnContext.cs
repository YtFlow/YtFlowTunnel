using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace YtFlow.Tunnel
{
    internal class DebugVpnContext
    {
        // private DatagramSocket s;
        internal UdpClient u;
        internal TunInterface tun;
        private int tunEndpoint;
        internal IPEndPoint pluginEndpoint = new IPEndPoint(new IPAddress(new byte[] { 127, 0, 0, 1 }), 9007);

        public DebugVpnContext ()
        {
#if !YT_MOCK
            tun = new TunInterface();
            tun.PacketPoped += Tun_PacketPoped;
#endif
        }
        public int Init (int pluginPort)
        {
            u = new UdpClient();
            u.Client.Bind(new IPEndPoint(pluginEndpoint.Address, 0));
            tunEndpoint = ((IPEndPoint)u.Client.LocalEndPoint).Port;
#if !YT_MOCK
            pluginEndpoint.Port = pluginPort;
            // s = new DatagramSocket();
            // s.MessageReceived += S_MessageReceived;
            // s.BindEndpointAsync(new HostName("127.0.0.1"), port).AsTask().Wait();
            // s.ConnectAsync(new HostName("127.0.0.1"), "9007").AsTask().Wait();
            tun?.Init();
            StartRecv();
#endif
            outPackets = Channel.CreateUnbounded<byte[]>();
            return tunEndpoint;
        }
        private async void StartRecv ()
        {
            while (u != null)
            {
                try
                {
                    var recv = await u.ReceiveAsync().ConfigureAwait(false);
                    tun?.PushPacket(recv.Buffer);
                }
                catch (ObjectDisposedException) { }
                catch (Exception ex)
                {
                    DebugLogger.Log("Error receiving from packet processor: " + ex.ToString());
                }
            }
        }
        public void Stop ()
        {
            // s?.Dispose();
            // s = null;
            tun?.Deinit();
            u?.Dispose();
            u = null;
            _ = outPackets.Writer.TryComplete();
        }

        internal Channel<byte[]> outPackets;
        private void Tun_PacketPoped (object sender, byte[] e)
        {
            // await packetPopLock.WaitAsync().ConfigureAwait(false);
            try
            {
                // await s?.OutputStream.WriteAsync(e.AsBuffer());
                // await (u?.SendAsync(e, e.Length, pluginEndpoint) ?? Task.CompletedTask).ConfigureAwait(false);
                _ = outPackets.Writer.TryWrite(e);
            }
            catch (Exception ex)
            {
                DebugLogger.Log("Error popping a packet: " + ex.ToString());
            }
            finally
            {
                // packetPopLock.Release();
            }
        }

        private void S_MessageReceived (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            using (var reader = args.GetDataReader())
            {
                byte[] b = new byte[reader.UnconsumedBufferLength];
                reader.ReadBytes(b);
                tun?.PushPacket(b);
            }
        }
    }
}
