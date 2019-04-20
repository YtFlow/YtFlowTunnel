using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace YtFlow.Tunnel
{
    internal class VpnContext
    {
        public VpnContext(VpnChannel channel)
        {
            this.channel = channel;
        }
        private VpnChannel channel;
        private DatagramSocket s;
        private TunInterface tun = new TunInterface();
        public ConcurrentQueue<byte[]> PendingPackets = new ConcurrentQueue<byte[]>();
        public void Init(string port)
        {
            s = new DatagramSocket();
            s.MessageReceived += S_MessageReceived;
            s.BindEndpointAsync(new HostName("127.0.0.1"), "9008").AsTask().Wait();
            s.ConnectAsync(new HostName("127.0.0.1"), "9007").AsTask().Wait();
            tun.Init();
            tun.PacketPoped += Tun_PacketPoped;

        }

        private static byte[] DUMMY_BYTES = new byte[] { 0x00 };
        private void Tun_PacketPoped(object sender, byte[] e)
        {
            // s.OutputStream.WriteAsync(e.AsBuffer()).AsTask();
            channel.LogDiagnosticMessage("Poped one packet");
            PendingPackets.Enqueue(e);
            CheckPendingPacket();
        }

        private byte[] DUMMY_BUFFER = new byte[2] { 0, 0 };
        private void S_MessageReceived(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            var reader = args.GetDataReader();
            reader.ReadBytes(DUMMY_BUFFER);
            // tun.PushPacket(b);
        }

        public void PushPacket(byte[] packet)
        {
            channel.LogDiagnosticMessage("Pushed one packet");
            tun.PushPacket(packet);
        }
        public async void CheckPendingPacket()
        {
            await s.OutputStream.WriteAsync(DUMMY_BYTES.AsBuffer());
        }
    }
}
