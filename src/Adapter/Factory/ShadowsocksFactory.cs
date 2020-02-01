using System.Text;
using Wintun2socks;
using YtCrypto;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class ShadowsocksFactory : IAdapterFactory
    {
        private ShadowsocksConfig config { get; }
        private CryptorFactory cryptorFactory { get; }
        public ShadowsocksFactory (ShadowsocksConfig config)
        {
            this.config = config;
            cryptorFactory = new CryptorFactory(config.Method, Encoding.UTF8.GetBytes(config.Password));
        }
        public TunSocketAdapter CreateAdapter (TcpSocket socket, TunInterface tun)
        {
            return new ShadowsocksAdapter(config.ServerHost, config.ServerPort, cryptorFactory.CreateCryptor(), socket, tun);
        }
    }
}
