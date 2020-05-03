using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class HttpFactory : IRemoteAdapterFactory
    {
        private HttpConfig config { get; set; }
        private readonly string serviceName;
        public HttpFactory (HttpConfig config)
        {
            this.config = config;
            serviceName = config.ServerPort.ToString();
        }
        public IRemoteAdapter CreateAdapter ()
        {
            return new HttpAdapter(config.ServerHost, serviceName);
        }
    }
}
