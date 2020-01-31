using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Wintun2socks;
using YtFlow.Tunnel.Adapter.Factory;
using YtFlow.Tunnel.Config;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    public delegate void PacketPopedHandler (object sender, [ReadOnlyArray] byte[] e);
    public sealed class TunInterface
    {
        Channel<Action> taskChannel;
        List<WeakReference<TunSocketAdapter>> adapters = new List<WeakReference<TunSocketAdapter>>();
        Wintun w = Wintun.Instance;
        DnsProxyServer dnsServer = new DnsProxyServer();
        bool running = false;
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

            w.PacketPoped += W_PopPacket;
            w.DnsPacketPoped += W_DnsPacketPoped;
            TcpSocket.EstablishedTcp += W_EstablishTcp;

            w.Init();
            int i = 0;
            while (running)
            {
                i++;
                await executeLwipTask(() =>
                {
                    w.CheckTimeout();
                    return 0;
                }).ConfigureAwait(false);
                await Task.Delay(250).ConfigureAwait(false);
                if (i % 10 == 0)
                {
                    adapters.RemoveAll(w => !w.TryGetTarget(out var a) || a.IsShutdown == 1);
                    DebugLogger.Log("# of connections in local stack: " + ConnectionCount.ToString());
                    DebugLogger.Log("# of adapters: " + adapters.Count.ToString());
                }
            }
        }
        public async void Deinit ()
        {
            if (!running)
            {
                return;
            }
            DebugLogger.Log("Tun deinit req");
            foreach (var weakAdapter in adapters.Where(w => w.TryGetTarget(out var a) && a.IsShutdown != 0))
            {
                try
                {
                    weakAdapter.TryGetTarget(out var adapter);
                    adapter.Reset();
                }
                catch (Exception) { }
            }

            await Task.Delay(300).ConfigureAwait(false);
            w.Deinit();
            w.PacketPoped -= W_PopPacket;
            w.DnsPacketPoped -= W_DnsPacketPoped;
            TcpSocket.EstablishedTcp -= W_EstablishTcp;

            adapters.Clear();
            // To avoid problems after reconnecting
            // dnsServer.Clear();
            // dispatchWorker = null;
            running = false;
            taskChannel.Writer.TryComplete();
            // debugSocket?.Dispose();
            // debugSocket = null;
        }

        private async void W_DnsPacketPoped (object sender, byte[] e, uint addr, ushort port)
        {
            try
            {
                var res = await dnsServer.QueryAsync(e).ConfigureAwait(false);
                await executeLwipTask(() => w.PushDnsPayload(addr, port, res)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // DNS timeout?
            }
        }

        internal static IAdapterFactory adapterFactory { get; set; }

        private void W_EstablishTcp (TcpSocket socket)
        {
            var adapter = adapterFactory.CreateAdapter(socket, this);
            adapters.Add(new WeakReference<TunSocketAdapter>(adapter));
        }

        private void W_PopPacket (object sender, byte[] e)
        {
            PacketPoped?.Invoke(sender, e);
            var _ = DebugLogger.LogPacketWithTimestamp(e);
        }

        public async void PushPacket ([ReadOnlyArray] byte[] packet)
        {
            /*if (dispatchQ.Count < 100)*/
            byte ret = await executeLwipTask(() => w.PushPacket(packet)).ConfigureAwait(false);
            if (ret == 0)
            {
                var _ = DebugLogger.LogPacketWithTimestamp(packet);
            }
            else
            {
                DebugLogger.Logger($"Push packet of size {packet.Length} with result: {ret}");
            }
        }

        public ulong ConnectionCount { get => TcpSocket.ConnectionCount(); }
        public int TaskCount { get => throw new NotImplementedException(); }
    }
}
