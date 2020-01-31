using System;
using System.Threading.Tasks;
using Wintun2socks;

namespace YtFlow.Tunnel
{

    internal abstract class ProxyAdapter : TunSocketAdapter
    {
        protected bool RemoteDisconnected { get; set; } = false;
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
                FinishSendToRemote();
            }
        }

        protected Task RemoteReceived (Span<byte> e)
        {
            return Write(e);
        }

        protected abstract void SendToRemote (byte[] e);
        protected abstract void FinishSendToRemote (Exception ex = null);

        private void ProxyAdapter_ReadData (object sender, byte[] e)
        {
            SendToRemote(e);
        }

        private void ProxyAdapter_OnError (object sender, int err)
        {
            if (!RemoteDisconnected)
            {
                FinishSendToRemote(new LwipException(err));
            }
        }

        protected override void CheckShutdown ()
        {
            ReadData -= ProxyAdapter_ReadData;
            OnError -= ProxyAdapter_OnError;
            OnFinished -= ProxyAdapter_OnFinished;
            base.CheckShutdown();
        }
    }
}
