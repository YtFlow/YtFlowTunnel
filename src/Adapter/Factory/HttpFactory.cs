using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class HttpFactory : IRemoteAdapterFactory
    {
        private HttpConfig config { get; set; }
        public HttpFactory (HttpConfig config)
        {
            this.config = config;
        }
        public IRemoteAdapter CreateAdapter ()
        {
            return new HttpAdapter(config.ServerHost, config.ServerPort);
        }
    }
}
