using System.Runtime.Serialization;

namespace YtFlow.Tunnel.Config
{
    [DataContract]
    public sealed class TrojanConfig : IAdapterConfig
    {
        [IgnoreDataMember]
        public string Path { get; set; }

        [DataMember]
        public string AdapterType { get => "trojan"; set { } }

        [DataMember]
        public string ServerHost { get; set; }

        [DataMember]
        public int ServerPort { get; set; }

        [DataMember]
        public string Password { get; set; }

        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public bool AllowInsecure { get; set; }
    }
}
