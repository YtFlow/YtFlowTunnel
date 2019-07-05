using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking.Sockets;
using Windows.UI.Core;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    public delegate void PacketPopedHandler (object sender, [ReadOnlyArray] byte[] e);
    public sealed class TunInterface
    {
        ConcurrentQueue<Action> dispatchQ = new ConcurrentQueue<Action>();
        SemaphoreSlim dispatchLocker = new SemaphoreSlim(1, 100);
        // BlockingCollection<Action> dispatchWorks = new BlockingCollection<Action>();
        Task dispatchWorker;
        // EventWaitHandle dispatchWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        List<TunSocketAdapter> adapters = new List<TunSocketAdapter>();
        Wintun w = Wintun.Instance;
        DnsProxyServer dnsServer = new DnsProxyServer();
        bool running = false;

        public event PacketPopedHandler PacketPoped;

        internal void executeLwipTask (Action act)
        {
            dispatchQ.Enqueue(act);
            // dispatchWorks.Add(act);
            // dispatchWaitHandle.Set();
            if (dispatchLocker.CurrentCount == 0)
            {
                try
                {
                    dispatchLocker.Release();
                }
                catch (SemaphoreFullException) { }
            }
        }
        internal Task<TResult> executeLwipTask<TResult> (Func<TResult> act)
        {
            TaskCompletionSource<TResult> tcs = new TaskCompletionSource<TResult>();
            dispatchQ.Enqueue(() =>
            // dispatchWorks.Add(() =>
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
            if (dispatchLocker.CurrentCount == 0)
            {
                try
                {
                    dispatchLocker.Release();
                }
                catch (SemaphoreFullException) { }
            }
            // dispatchWaitHandle.Set();
            return tcs.Task;
        }
        private async void doWork ()
        {
            while (running)
            {
                Action act;
                if (!dispatchQ.TryDequeue(out act))
                // {
                // Debug.WriteLine($"{dispatchQ.Count} tasks remain");
                //Task.Run(() =>
                //if (!dispatchWorks.TryTake(out act, 250))
                {
                    await dispatchLocker.WaitAsync(250);
                    continue;
                }
                try
                {
#if YTLOG_VERBOSE
                        var sw = Stopwatch.StartNew();
#endif
                    act();
#if YTLOG_VERBOSE
                        Debug.WriteLine($"{dispatchWorks.Count} tasks remain {sw.ElapsedMilliseconds}");
#endif
                }//).Wait(2000);
                catch (Exception)
                {
                    await Task.Delay(10);
                }
                // dispatchWaitHandle.WaitOne();
            }
        }
        public async void Init (DatagramSocket outputSocket)
        {
            if (running)
            {
                return;
            }
            running = true;
            dispatchWorker = Task.Run(() => doWork());

            w.PacketPoped += W_PopPacket;
            w.DnsPacketPoped += W_DnsPacketPoped;
            TcpSocket.EstablishedTcp += W_EstablishTcp;

            w.Init(outputSocket);
            while (running)
            {
                await Task.Delay(250);
                await executeLwipTask(() =>
                {
                    w.CheckTimeout();
                    return 0;
                });
            }
        }
        public async void Deinit ()
        {
            if (!running)
            {
                return;
            }
            foreach (var adapter in adapters.Where(a => !a.IsShutdown))
            {
                try
                {
                    adapter.Reset();
                }
                catch (Exception) { }
            }

            await Task.Delay(300);
            w.Deinit();
            w.PacketPoped -= W_PopPacket;
            w.DnsPacketPoped -= W_DnsPacketPoped;
            TcpSocket.EstablishedTcp -= W_EstablishTcp;

            adapters.Clear();
            dnsServer.Clear();
            dispatchWorker = null;
            running = false;
        }

        private async void W_DnsPacketPoped (object sender, byte[] e, uint addr, ushort port)
        {
            try
            {
                var res = await dnsServer.QueryAsync(e).ConfigureAwait(false);
                await executeLwipTask(() => w.PushDnsPayload(addr, port, res));
            }
            catch (Exception)
            {
                // DNS timeout?
            }
        }

        private void W_EstablishTcp (TcpSocket socket)
        {
            // ShadowsocksR server with procotol=origin, method=aes-128-cfb
            var adapter = new RawShadowsocksAdapter("80.80.80.80", 1234, "yourpassword", socket, this);
            adapters.Add(adapter);
            if (adapters.Count > 150)
            {
                adapters.RemoveAll(a => a.IsShutdown);
            }
        }

        private void W_PopPacket (object sender, byte[] e)
        {
            PacketPoped?.Invoke(sender, e);
        }

        public void PushPacket ([ReadOnlyArray] byte[] packet)
        {
            /*if (dispatchQ.Count < 100)*/
            executeLwipTask(() => w.PushPacket(packet));
        }

        public uint ConnectionCount { get => TcpSocket.ConnectionCount(); }
        public int TaskCount { get => dispatchQ.Count; }
    }
}
