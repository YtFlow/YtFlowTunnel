using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace YtFlow.Tunnel.Config
{
    [DataContract]
    public sealed class TrojanConfig : IAdapterConfig
    {
        internal static readonly DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(TrojanConfig));
        public void SaveToFile (string filePath)
        {
            AdapterConfig.SaveToFile(this, filePath, serializer);
        }

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
