using System.Runtime.Serialization;

namespace YtFlow.Tunnel.Config
{
    [DataContract]
    public sealed class ShadowsocksConfig : IAdapterConfig
    {
        [IgnoreDataMember]
        public string Path { get; set; }

        [DataMember]
        public string AdapterType { get => "shadowsocks"; set { } }

        [DataMember]
        public string ServerHost { get; set; }

        [DataMember]
        public int ServerPort { get; set; }

        [DataMember]
        public string Method { get; set; }

        [DataMember]
        public string Password { get; set; }

        [DataMember]
        public string Name { get; set; }
    }
}
