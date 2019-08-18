using Wintun2socks;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class HttpFactory : IAdapterFactory
    {
        private HttpConfig config { get; set; }
        public HttpFactory (HttpConfig config)
        {
            this.config = config;
        }
        public TunSocketAdapter CreateAdapter (TcpSocket socket, TunInterface tun)
        {
            return new HttpAdapter(config.ServerHost, config.ServerPort, socket, tun);
        }
    }
}
