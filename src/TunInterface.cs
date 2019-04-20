using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.UI.Core;
using Wintun2socks;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel
{
    public delegate void PacketPopedHandler (object sender, [ReadOnlyArray] byte[] e);
    public sealed class TunInterface
    {
        // ConcurrentQueue<Action> dispatchQ = new ConcurrentQueue<Action>();
        BlockingCollection<Action> dispatchWorks = new BlockingCollection<Action>();
        Task dispatchWorker;
        EventWaitHandle dispatchWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        Wintun w = Wintun.Instance;
        DnsProxyServer dnsServer = new DnsProxyServer();
        Action<string> Write;
        Action<string> WriteLine;

        public event PacketPopedHandler PacketPoped;

        internal void executeLwipTask (Action act)
        {
            // dispatchQ.Enqueue(act);
            dispatchWorks.Add(act);
            // dispatchWaitHandle.Set();
        }
        internal Task<TResult> executeLwipTask<TResult> (Func<TResult> act)
        {
            TaskCompletionSource<TResult> tcs = new TaskCompletionSource<TResult>();
            // dispatchQ.Enqueue(() =>
            dispatchWorks.Add(() =>
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
            // dispatchWaitHandle.Set();
            return tcs.Task;
        }
        private async void doWork ()
        {
            while (true)
            {
                // while (dispatchQ.TryDequeue(out Action act))
                // {
                // Debug.WriteLine($"{dispatchQ.Count} tasks remain");
                //Task.Run(() =>
                if (!dispatchWorks.TryTake(out var act, 100))
                {
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
        public async void Init ()
        {
            WriteLine = Write = str =>
            {
                // logger(str);
                //return null;
            };
            dispatchWorker = Task.Run(() => doWork());

            w.PacketPoped += W_PopPacket;
            w.DnsPacketPoped += W_DnsPacketPoped;
            TcpSocket.EstablishedTcp += W_EstablishTcp;

            w.Init();
            while (true)
            {
                await Task.Delay(250);
                await executeLwipTask(() =>
                {
                    w.CheckTimeout();
                    return 0;
                });
            }
        }

        private async void W_DnsPacketPoped (object sender, byte[] e, uint addr, ushort port)
        {
            try
            {
                var res = await dnsServer.QueryAsync(e);
                await executeLwipTask(() => w.PushDnsPayload(addr, port, new List<byte>(res).ToArray()));
            }
            catch (Exception)
            {
                // DNS timeout?
            }
        }

        private void W_EstablishTcp (TcpSocket socket)
        {
            Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            // ShadowsocksR server with procotol=origin, method=aes-128-cfb
            new RawShadowsocksAdapter("80.80.80.80", 1234, "yourpassword", socket, this);
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
        public int TaskCount { get => dispatchWorks.Count; }
    }
}
