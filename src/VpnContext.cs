using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace YtFlow.Tunnel
{
    internal class VpnContext
    {
        public VpnContext (VpnChannel channel)
        {
            this.channel = channel;
            s = new DatagramSocket();
            s.MessageReceived += S_MessageReceived;
            s.BindEndpointAsync(new HostName("127.0.0.1"), "9008").AsTask().Wait();
            s.ConnectAsync(new HostName("127.0.0.1"), "9007").AsTask().Wait();
            tun.PacketPoped += Tun_PacketPoped;
        }
        private VpnChannel channel;
        private DatagramSocket s;
        private TunInterface tun = new TunInterface();
        public ConcurrentQueue<byte[]> PendingPackets = new ConcurrentQueue<byte[]>();
        public ConcurrentQueue<byte[]> InputPackets = new ConcurrentQueue<byte[]>();
        public SemaphoreSlim InputLock = new SemaphoreSlim(1, 100);
        public async void Init ()
        {
            tun?.Init();
            connected = true;
            //while (connected)
            {
                //await Task.Delay(250);
                //channel.LogDiagnosticMessage("Timer checking");
                //await CheckPendingPacket();
            }
        }
        public void Stop ()
        {
            connected = false;
            tun?.Deinit();
        }

        private static byte[] DUMMY_BYTES = new byte[] { 0x00 };
        private bool connected;

        private void Tun_PacketPoped (object sender, byte[] e)
        {
            //s.OutputStream.WriteAsync(e.AsBuffer()).AsTask();
            //channel.LogDiagnosticMessage("Poped one packet");
            PendingPackets.Enqueue(e);
            CheckPendingPacket();
        }

        private void S_MessageReceived (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            CheckPendingPacket();
            var reader = args.GetDataReader();
            byte[] b = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(b);
            tun?.PushPacket(b);
            /*while (InputPackets.TryDequeue(out var packet))
            {
                tun?.PushPacket(packet);
            }*/
        }

        public void PushPacket (byte[] packet)
        {
            //channel.LogDiagnosticMessage("Pushed one packet");
            tun?.PushPacket(packet);
        }
        public async Task CheckPendingPacket ()
        {
            //do
            {
                //channel.LogDiagnosticMessage("Checking packets: " + PendingPackets.Count);
                await s.OutputStream.WriteAsync(DUMMY_BYTES.AsBuffer());
                //await Task.Delay(10);
                //channel.LogDiagnosticMessage("Checking packet sent");
            }
            //while (!PendingPackets.IsEmpty);
        }
    }
}
