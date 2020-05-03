using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal class TunDatagramAdapter : ILocalAdapter
    {
        private const int TIMEOUT = 60;
        private const uint DNS_ADDRESS = 0x01010101U;
        private const ushort DNS_PORT = 53;
        private static readonly NotSupportedException UdpMethodNotSupported = new NotSupportedException("This method call is not supported for UDP sockets.");
        internal static readonly Dictionary<(ushort LocalPort, Destination.Destination Remote), TunDatagramAdapter> socketMap = new Dictionary<(ushort, Destination.Destination), TunDatagramAdapter>();
        private static readonly ArrayPool<byte> udpPayloadArrayPool = ArrayPool<byte>.Create();
        private static readonly ChannelReader<byte[]> CompletedChannelReader = CreateCompletedChannelReader();
        private readonly TunInterface tun;
        private readonly uint localAddr;
        private readonly ushort localPort;
        private readonly byte[] sendBuffer = new byte[1500];
        private readonly Task initTask;
        private readonly IRemoteAdapter remoteAdapter;
        private int secondsTicked = 0;
        public Destination.Destination Destination { get; set; }

        private static ChannelReader<byte[]> CreateCompletedChannelReader ()
        {
            var channel = Channel.CreateBounded<byte[]>(1);
            channel.Writer.Complete();
            return channel.Reader;
        }

        internal TunDatagramAdapter (TunInterface tun, IRemoteAdapter remoteAdapter, Destination.Destination destination, uint localAddr, ushort localPort)
        {
            this.localAddr = localAddr;
            this.localPort = localPort;
            this.tun = tun;
            Destination = destination;
            this.remoteAdapter = remoteAdapter;
            initTask = remoteAdapter.Init(CompletedChannelReader, this).AsTask().ContinueWith(t =>
            {
                if (t.IsCanceled || t.IsFaulted)
                {
                    DebugLogger.Log($"Error initiating a connection to {Destination}: {t.Exception}");
                    remoteAdapter.RemoteDisconnected = true;
                    CheckShutdown();
                }
                else
                {
                    if (DebugLogger.LogNeeded())
                    {
                        DebugLogger.Log("Connected: " + Destination.ToString());
                    }
                    _ = StartForward().ConfigureAwait(false);
                }
                return t;
            }).Unwrap();
        }

        private async Task StartForward ()
        {
            var recvCancel = new CancellationTokenSource();
            var sendCancel = new CancellationTokenSource();
            var timeoutCancel = new CancellationTokenSource();
            var _timeoutTask = Task.Run(async () =>
              {
                  while (secondsTicked < TIMEOUT)
                  {
                      await Task.Delay(1000, timeoutCancel.Token);
                      Interlocked.Increment(ref secondsTicked);
                  }
                  if (remoteAdapter?.RemoteDisconnected == false)
                  {
                      sendCancel?.Cancel();
                      recvCancel?.Cancel();
                  }
              });
            try
            {
                await remoteAdapter.StartRecvPacket(this, recvCancel.Token).ConfigureAwait(false);
                if (DebugLogger.LogNeeded())
                {
                    DebugLogger.Log("Close!: " + Destination);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                DebugLogger.Log($"Recv error: {Destination}: {ex}");
            }
            finally
            {
                if (remoteAdapter != null)
                {
                    remoteAdapter.RemoteDisconnected = true;
                }
                timeoutCancel.Cancel();
                sendCancel?.Cancel();
                recvCancel.Dispose();
                timeoutCancel.Dispose();
            }
            CheckShutdown();
        }

        /// <summary>
        /// Write a UDP packet to local. Call site must wait until the Task completes before writing another packet.
        /// </summary>
        /// <param name="data">Data to write</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public unsafe ValueTask WritePacketToLocal (Span<byte> data, CancellationToken cancellationToken = default)
        {
            // TODO: which source address to use?
            Ipv4Host src;
            switch (Destination.Host)
            {
                case Ipv4Host ipv4Host:
                    src = ipv4Host;
                    break;
                case DomainNameHost domainNameHost:
                    if (DnsProxyServer.ReverseQuery(domainNameHost.DomainName, out var domainNameIpHost))
                    {
                        src = domainNameIpHost;
                    }
                    else
                    {
                        return new ValueTask();
                    }
                    break;
                default:
                    // TODO: IPv6
                    throw UdpMethodNotSupported;
            }
            secondsTicked = 0;
            data.CopyTo(sendBuffer);
            var len = data.Length;
            return WriteUdpPacket(src.Data, Destination.Port, localAddr, localPort, sendBuffer, (ushort)len);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe byte UnsafeWriteUdpPacket (uint src, ushort port, uint localAddr, ushort localPort, byte[] sendBuffer, ushort len)
        {
            fixed (byte* ptr = sendBuffer)
            {
                return tun.wintun.PushUdpPayload(src, port, localAddr, localPort, (ulong)ptr, len);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private async ValueTask WriteUdpPacket (uint src, ushort port, uint localAddr, ushort localPort, byte[] sendBuffer, ushort len)
        {
            await tun.executeLwipTask(() => UnsafeWriteUdpPacket(src, port, localAddr, localPort, sendBuffer, len));
        }

        public void CheckShutdown ()
        {
            var entry = (localPort, Destination);
            if (socketMap.TryGetValue(entry, out var socket) && socket == this)
            {
                socketMap.Remove(entry);
            }
            remoteAdapter.CheckShutdown();
        }

        internal static async void ProcessIpPayload (byte[] packet, TunInterface tun)
        {
            if (packet.Length < 28)
            {
                return;
            }
            var srcIp = BitConverter.ToUInt32(packet, 12);
            var dstIp = BitConverter.ToUInt32(packet, 16);
            ushort srcPort = (ushort)((packet[20] << 8) | (packet[21] & 0xFF));
            ushort dstPort = (ushort)((packet[22] << 8) | (packet[23] & 0xFF));
            var payload = packet.AsMemory(28);
            if (dstIp == DNS_ADDRESS && dstPort == DNS_PORT)
            {
                // DNS request
                var resBuf = udpPayloadArrayPool.Rent(1000); // The length of a domain name cannot exceed 255 bytes
                try
                {
                    var len = await DnsProxyServer.QueryAsync(payload, resBuf.AsMemory()).ConfigureAwait(false);
                    if (len <= 0)
                    {
                        return;
                    }
                    var buf = resBuf.AsBuffer(0, len);
                    await tun.executeLwipTask(() => tun.wintun.PushDnsPayload(srcIp, srcPort, buf)).ConfigureAwait(false);
                }
                finally
                {
                    udpPayloadArrayPool.Return(resBuf);
                }
            }
            else
            {
                // General UDP packet
                var destination = new Destination.Destination(DnsProxyServer.TryLookup(dstIp), dstPort, TransportProtocol.Udp);
                var entry = (srcPort, destination);
                if (!socketMap.TryGetValue(entry, out var socket))
                {
                    socket = new TunDatagramAdapter(tun, TunInterface.adapterFactory.CreateAdapter(), destination, srcIp, srcPort);
                    socketMap[entry] = socket;
                }
                if (socket.remoteAdapter?.RemoteDisconnected == false)
                {
                    try
                    {
                        await socket.initTask.ConfigureAwait(false);
                        socket.remoteAdapter?.SendPacketToRemote(payload, destination);
                    }
                    catch (Exception ex)
                    {
                        DebugLogger.Log("Error sending UDP payload: " + ex.ToString());
                        socket?.CheckShutdown();
                    }
                }
            }
        }
    }
}
