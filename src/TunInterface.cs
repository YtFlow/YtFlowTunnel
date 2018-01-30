using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Wintun2socks;

namespace YtFlowTunnel
{
    public delegate void PacketPopedHandler(object sender, [ReadOnlyArray] byte[] e);
    public sealed class TunInterface
    {
        ConcurrentQueue<Action> dispatchQ = new ConcurrentQueue<Action>();
        Task dispatchWorker;
        Task worker;
        EventWaitHandle dispatchWaitHandle = new EventWaitHandle(false, EventResetMode.ManualReset);
        EventWaitHandle timeoutWaitHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        Wintun w = Wintun.Instance;
        Action<string> Write;
        Action<string> WriteLine;

        public event PacketPopedHandler PacketPoped;

        internal void executeLwipTask(Action act)
        {
            dispatchQ.Enqueue(act);
            dispatchWaitHandle.Set();
        }
        public void Init()
        {
            WriteLine = Write = str =>
            {
                // logger(str);
                //return null;
            };
            dispatchWorker = Task.Run(() =>
            {
                while (true)
                {
                    Debug.WriteLine($"{dispatchQ.Count} tasks remain");
                    while (dispatchQ.TryDequeue(out Action act))
                    {
                        timeoutWaitHandle.Reset();
                        worker = Task.Run(() =>
                        {
                            act();
                            timeoutWaitHandle.Set();
                        });
                        timeoutWaitHandle.Reset();
                        timeoutWaitHandle.WaitOne(2000);
                    }
                    dispatchWaitHandle.Reset();
                    dispatchWaitHandle.WaitOne();
                }
            });

            w.PacketPoped += W_PopPacket;
            TcpSocket.EstablishedTcp += W_EstablishTcp;

            w.Init();
        }

        private void W_EstablishTcp(TcpSocket socket)
        {
            Debug.WriteLine($"{TcpSocket.ConnectionCount()} connections now");
            // ShadowsocksR server with procotol=origin, method=none
            RawShadowsocksAdapter a = new RawShadowsocksAdapter("80.80.80.80", 1234, socket, this);
        }

        private void W_PopPacket(object sender, byte[] e)
        {
            PacketPoped(sender, e);
        }

        public void PushPacket([ReadOnlyArray] byte[] packet)
        {
            executeLwipTask(() => w.PushPacket(packet));
        }
    }
}
