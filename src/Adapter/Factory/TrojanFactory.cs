﻿using System;
using System.Text;
using Windows.Networking;
using Wintun2socks;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal class TrojanFactory : IAdapterFactory
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
            var hashResult = YtCrypto.Common.Sha224(Encoding.UTF8.GetBytes(config.Password), keyBuf);
            if (hashResult != 0)
            {
                throw new Exception("Cannot hash Trojan password, result = " + hashResult.ToString());
            }
            hashedKey = Encoding.ASCII.GetBytes(BitConverter.ToString(keyBuf).Replace("-", string.Empty).ToLower()).AsMemory(0, 56);
        }
        public TunSocketAdapter CreateAdapter (TcpSocket socket, TunInterface tun)
        {
            return new TrojanAdapter(host, serviceName, hashedKey, allowInsecure, socket, tun);
        }
    }
}
