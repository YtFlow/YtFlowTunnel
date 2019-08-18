using System;
using Wintun2socks;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class TrojanFactory : IAdapterFactory
    {
        private TrojanConfig config { get; set; }
        public TrojanFactory (TrojanConfig config)
        {
            this.config = config;
        }
        public TunSocketAdapter CreateAdapter (TcpSocket socket, TunInterface tun)
        {
            // TODO: hash password
            throw new NotImplementedException("Trojan adapter is not implemented");
            // return new TrojanAdapter(config.ServerHost, config.ServerPort, , socket, tun);
        }
    }
}
