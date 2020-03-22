using System;
using System.Text;
using Windows.Networking;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class TrojanFactory : IRemoteAdapterFactory
    {
        private Memory<byte> hashedKey { get; }
        private HostName host { get; }
        private string serviceName { get; }
        private bool allowInsecure { get; }
        public TrojanFactory (TrojanConfig config)
        {
            host = new HostName(config.ServerHost);
            serviceName = config.ServerPort.ToString();
            allowInsecure = config.AllowInsecure;
            var keyBuf = new byte[32];
            YtCrypto.Util.Sha224(Encoding.UTF8.GetBytes(config.Password), keyBuf);
            hashedKey = Encoding.ASCII.GetBytes(BitConverter.ToString(keyBuf).Replace("-", string.Empty).ToLower()).AsMemory(0, 56);
        }
        public IRemoteAdapter CreateAdapter ()
        {
            return new TrojanAdapter(host, serviceName, hashedKey, allowInsecure);
        }
    }
}
