using System.Text;
using YtCrypto;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class ShadowsocksFactory : IRemoteAdapterFactory
    {
        private ShadowsocksConfig config { get; }
        internal static CryptorFactory GlobalCryptorFactory { get; set; }
        private CryptorFactory CryptorFactory { get; set; }
        private bool isAead = false;
        public ShadowsocksFactory (ShadowsocksConfig config)
        {
            this.config = config;
            var lowerMethod = config.Method.ToLower();
            if (lowerMethod.EndsWith("gcm") || lowerMethod == "chacha20-ietf-poly1305")
            {
                isAead = true;
            }
            GlobalCryptorFactory = CryptorFactory = new CryptorFactory(config.Method, Encoding.UTF8.GetBytes(config.Password));
        }

        public IRemoteAdapter CreateAdapter ()
        {
            if (isAead)
            {
                return new ShadowsocksAeadAdapter(config.ServerHost, config.ServerPort, CryptorFactory.CreateCryptor());
            }
            else
            {
                return new ShadowsocksAdapter(config.ServerHost, config.ServerPort, CryptorFactory.CreateCryptor());
            }
        }
    }
}
