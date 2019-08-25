using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace YtFlow.Tunnel
{
    internal class DebugVpnContext
    {
        private DatagramSocket s;
        private TunInterface tun;
        private readonly string port;

        public DebugVpnContext()
        {

        }
        public DebugVpnContext(string port)
        {
            tun = new TunInterface();
            tun.PacketPoped += Tun_PacketPoped;
            this.port = port;
        }
        public void Init()
        {
            s = new DatagramSocket();
            s.MessageReceived += S_MessageReceived;
            s.BindEndpointAsync(new HostName("127.0.0.1"), port).AsTask().Wait();
            s.ConnectAsync(new HostName("127.0.0.1"), "9007").AsTask().Wait();
            tun?.Init();
        }
        public void Stop()
        {
            s.Dispose();
            tun?.Deinit();
        }

        private void Tun_PacketPoped(object sender, byte[] e)
        {
            var _ = s.OutputStream.WriteAsync(e.AsBuffer());
        }

        private void S_MessageReceived(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            var remotePort = args.RemotePort;
            var reader = args.GetDataReader();
            byte[] b = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(b);
            tun.PushPacket(b);
        }
    }
}
