using Wintun2socks;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal interface IAdapterFactory
    {
        TunSocketAdapter CreateAdapter (TcpSocket socket, TunInterface tun);
    }
}
