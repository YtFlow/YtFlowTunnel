using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Storage.Streams;
using Wintun2socks;

namespace YtFlow.Tunnel
{
    internal abstract class ProxyAdapter : TunSocketAdapter
    {
        protected bool RemoteDisconnecting { get; set; } = false;
        protected bool RemoteDisconnected { get; set; } = false;
        public override bool IsShutdown => LocalDisconnected && RemoteDisconnected;
        public ProxyAdapter (TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            ReadData += ProxyAdapter_ReadData;
            OnError += ProxyAdapter_OnError;
            OnFinished += ProxyAdapter_OnFinished;
        }

        protected void ProxyAdapter_OnFinished (object sender)
        {
            if (!RemoteDisconnected)
            {
                DisconnectRemote();
            }
        }

        protected virtual Task RemoteReceived (Memory<byte> e)
        {
            return Write(e);
        }

        protected abstract void SendToRemote (byte[] e);
        protected abstract void DisconnectRemote ();

        private void ProxyAdapter_ReadData (object sender, byte[] e)
        {
            SendToRemote(e);
        }

        private void ProxyAdapter_OnError (object sender, int err)
        {
            // Close();
            DisconnectRemote();
        }

        protected override void CheckShutdown ()
        {
            if (IsShutdown)
            {
                ReadData -= ProxyAdapter_ReadData;
                OnError -= ProxyAdapter_OnError;
                OnFinished -= ProxyAdapter_OnFinished;
            }
            base.CheckShutdown();
        }
    }
}
