using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Channels;
using System.Threading.Tasks;
using Wintun2socks;
using YtFlow.Tunnel.Adapter.Factory;
using YtFlow.Tunnel.Adapter.Local;
using YtFlow.Tunnel.Adapter.Relay;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel
{
    public delegate void PacketPopedHandler (object sender, [ReadOnlyArray] byte[] e);
    public sealed class TunInterface
    {
        private const uint RELAY_ADDRESS = 0xF0FF11ACu; // 172.17.255.240 in network endianness
        private Channel<Action> taskChannel;
        private readonly List<WeakReference<TunSocketAdapter>> tunAdapters = new List<WeakReference<TunSocketAdapter>>();
        internal Wintun wintun = Wintun.Instance;
        private bool running = false;
        public event PacketPopedHandler PacketPoped;

        internal bool executeLwipTask (Action act)
        {
            return taskChannel.Writer.TryWrite(act);
        }

        internal Task<TResult> executeLwipTask<TResult> (Func<TResult> act)
        {
            TaskCompletionSource<TResult> tcs = new TaskCompletionSource<TResult>();
            taskChannel.Writer.TryWrite(() =>
            {
                try
                {
                    var res = act();
                    tcs.TrySetResult(res);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            });
            return tcs.Task;
        }

        private async void doWork ()
        {
            while (await taskChannel.Reader.WaitToReadAsync())
            {
                taskChannel.Reader.TryRead(out var act);
                try
                {
#if YTLOG_VERBOSE
                        var sw = Stopwatch.StartNew();
#endif
                    act();
#if YTLOG_VERBOSE
                        //Debug.WriteLine($"{dispatchWorks.Count} tasks remain {sw.ElapsedMilliseconds}");
#endif
                }
                catch (Exception e)
                {
                    DebugLogger.Log("Error from task queue: " + e.ToString());
                }
            }
        }

        public async void Init ()
        {
            if (running)
            {
                return;
            }
            running = true;
            adapterFactory = AdapterConfig.GetAdapterFactoryFromDefaultFile();
            taskChannel = Channel.CreateUnbounded<Action>(new UnboundedChannelOptions()
            {
                SingleReader = true
            });
            var _ = Task.Run(() => doWork());

            wintun.PacketPoped += W_PopPacket;
            TcpSocket.EstablishedTcp += W_EstablishTcp;

            wintun.Init();
            int i = 0;
            while (running)
            {
                i++;
                await executeLwipTask(() =>
                {
                    wintun.CheckTimeout();
                    return 0;
                }).ConfigureAwait(false);
                if (i % 10 == 0)
                {
                    tunAdapters.RemoveAll(w => !w.TryGetTarget(out var a) /* TODO: || a.IsShutdown == 1 */);
                    if (DebugLogger.LogNeeded())
                    {
                        DebugLogger.Log("# of connections in local stack: " + ConnectionCount);
                        DebugLogger.Log($"# of open/all adapters: {TunSocketAdapter.OpenCount} {tunAdapters.Count}");
                        DebugLogger.Log($"# of recv/send: {TunSocketAdapter.RecvingCount} {TunSocketAdapter.SendingCount}");
                    }
                }
                await Task.Delay(250).ConfigureAwait(false);
            }
        }

        public async void Deinit ()
        {
            if (!running)
            {
                return;
            }
            DebugLogger.Log("Tun deinit req");
            foreach (var weakAdapter in tunAdapters.Where(w => w.TryGetTarget(out var a) /* TODO: && a.IsShutdown != 0 */))
            {
                try
                {
                    weakAdapter.TryGetTarget(out var adapter);
                    adapter.Reset();
                }
                catch (Exception) { }
            }

            TunDatagramAdapter.socketMap.Clear();
            await Task.Delay(300).ConfigureAwait(false);
            wintun.Deinit();
            wintun.PacketPoped -= W_PopPacket;
            TcpSocket.EstablishedTcp -= W_EstablishTcp;

            tunAdapters.Clear();
            // To avoid problems after reconnecting
            // dnsServer.Clear();
            // dispatchWorker = null;
            running = false;
            taskChannel.Writer.TryComplete();
            // debugSocket?.Dispose();
            // debugSocket = null;
            DebugLogger.initNeeded = null;
        }

        internal static IRemoteAdapterFactory adapterFactory { get; set; }

        private void W_EstablishTcp (TcpSocket socket)
        {
            if (socket.RemoteAddr == RELAY_ADDRESS && socket.RemotePort == 1080)
            {
                var remoteAdapter = adapterFactory.CreateAdapter();
                var localAdapter = new TunSocketAdapter(socket, this, new Socks5Relay(remoteAdapter));
                tunAdapters.Add(new WeakReference<TunSocketAdapter>(localAdapter));
            }
            else
            {
                var remoteAdapter = adapterFactory.CreateAdapter();
                tunAdapters.Add(new WeakReference<TunSocketAdapter>(new TunSocketAdapter(socket, this, remoteAdapter)));
            }
        }

        private void W_PopPacket (object sender, byte[] e)
        {
            if (DebugLogger.LogNeeded())
            {
                var _ = DebugLogger.LogPacketWithTimestamp(e);
            }
            PacketPoped?.Invoke(sender, e);
        }

        public async void PushPacket ([ReadOnlyArray] byte[] packet)
        {
            // Packets must contain valid IPv4 headers
            if (packet.Length < 20 || packet[0] >> 4 != 4)
            {
                return;
            }
            var proto = packet[9];
            switch (proto)
            {
                case 6: // TCP
                    break;
                case 17: // UDP
                    break;
                default:
                    return;
            }
            if (DebugLogger.LogNeeded())
            {
                var _ = DebugLogger.LogPacketWithTimestamp(packet);
            }
            if (proto == 6)
            {
                byte ret = await executeLwipTask(() => wintun.PushPacket(packet)).ConfigureAwait(false);
            }
            else
            {
                try
                {
                    TunDatagramAdapter.ProcessIpPayload(packet, this);
                }
                catch (Exception ex)
                {
                    DebugLogger.Log("Error processing udp ip packet: " + ex.ToString());
                }
            }
        }

        public ulong ConnectionCount { get => TcpSocket.ConnectionCount(); }
        public int TaskCount { get => throw new NotImplementedException(); }
    }
}
