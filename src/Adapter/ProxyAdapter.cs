using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Storage.Streams;
using Wintun2socks;

namespace YtFlow.Tunnel
{
    internal abstract class ProxyAdapter : TunSocketAdapter
    {
        public ProxyAdapter(TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            ReadData += ProxyAdapter_ReadData;
            OnError += ProxyAdapter_OnError;
            OnFinished += ProxyAdapter_OnFinished;
        }

        private void ProxyAdapter_OnFinished (object sender)
        {
            DisconnectRemote();
        }

        protected virtual void RemoteReceived(IBuffer e)
        {
            Write(e);
        }

        protected abstract void SendToRemote(byte[] e);
        protected abstract void DisconnectRemote();

        private void ProxyAdapter_ReadData(object sender, byte[] e)
        {
            SendToRemote(e);
        }

        private void ProxyAdapter_OnError(object sender, int err)
        {
            // Close();
            DisconnectRemote();
        }

    }
}
