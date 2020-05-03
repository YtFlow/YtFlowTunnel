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
        private readonly bool isAead = false;
        private readonly string serviceName;
        public ShadowsocksFactory (ShadowsocksConfig config)
        {
            this.config = config;
            serviceName = config.ServerPort.ToString();
            var lowerMethod = config.Method.ToLower();
            if (lowerMethod.EndsWith("gcm") || lowerMethod.EndsWith("poly1305"))
            {
                isAead = true;
            }
            GlobalCryptorFactory = CryptorFactory = CryptorFactory.CreateFactory(config.Method, Encoding.UTF8.GetBytes(config.Password));
        }

        public IRemoteAdapter CreateAdapter ()
        {
            if (isAead)
            {
                return new ShadowsocksAeadAdapter(config.ServerHost, serviceName, CryptorFactory.CreateCryptor());
            }
            else
            {
                return new ShadowsocksAdapter(config.ServerHost, serviceName, CryptorFactory.CreateCryptor());
            }
        }
    }
}
