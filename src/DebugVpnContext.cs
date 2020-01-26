using System;
using System.Net;
using System.Net.Sockets;
using Windows.Networking.Sockets;

namespace YtFlow.Tunnel
{
    internal class DebugVpnContext
    {
        // private DatagramSocket s;
        private UdpClient u;
        private TunInterface tun;
        private readonly string port;

        public DebugVpnContext () : this("9008")
        {

        }
        public DebugVpnContext (string port)
        {
#if !YT_MOCK
            tun = new TunInterface();
            tun.PacketPoped += Tun_PacketPoped;
            this.port = port;
#endif
        }
        public void Init ()
        {
#if !YT_MOCK
            u = new UdpClient(int.Parse(port));
            // s = new DatagramSocket();
            // s.MessageReceived += S_MessageReceived;
            // s.BindEndpointAsync(new HostName("127.0.0.1"), port).AsTask().Wait();
            // s.ConnectAsync(new HostName("127.0.0.1"), "9007").AsTask().Wait();
            tun?.Init();
            StartRecv();
#endif
        }
        private async void StartRecv ()
        {
            while (u != null)
            {
                try
                {
                    var recv = await u.ReceiveAsync();
                    tun?.PushPacket(recv.Buffer);
                }
                catch (Exception) { break; }
            }
        }
        public void Stop ()
        {
            // s.Dispose();
            u?.Dispose();
            u = null;
            tun?.Deinit();
        }

        private IPEndPoint pluginEndpoint = new IPEndPoint(new IPAddress(new byte[] { 127, 0, 0, 1 }), 9007);
        private async void Tun_PacketPoped (object sender, byte[] e)
        {
            // var _ = s.OutputStream.WriteAsync(e.AsBuffer());
            await u?.SendAsync(e, e.Length, pluginEndpoint);
        }

        private void S_MessageReceived (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            var reader = args.GetDataReader();
            byte[] b = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(b);
            tun.PushPacket(b);
        }
    }
}
