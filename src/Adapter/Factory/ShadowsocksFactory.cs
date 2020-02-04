using System.Text;
using YtCrypto;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class ShadowsocksFactory : IRemoteAdapterFactory
    {
        private ShadowsocksConfig config { get; }
        private CryptorFactory cryptorFactory { get; }
        public ShadowsocksFactory (ShadowsocksConfig config)
        {
            this.config = config;
            cryptorFactory = new CryptorFactory(config.Method, Encoding.UTF8.GetBytes(config.Password));
        }
        public IRemoteAdapter CreateAdapter ()
        {
            return new ShadowsocksAdapter(config.ServerHost, config.ServerPort, cryptorFactory.CreateCryptor());
        }
    }
}
