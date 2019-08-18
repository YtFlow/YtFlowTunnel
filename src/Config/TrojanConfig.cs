using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace YtFlow.Tunnel.Config
{
    [DataContract]
    public sealed class TrojanConfig : IAdapterConfig
    {
        private static DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(TrojanConfig));
        internal static TrojanConfig GetConfigFromFilePath (string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                var config = serializer.ReadObject(stream) as TrojanConfig;
                if (config != null)
                {
                    config.Path = filePath;
                }
                return config;
            }
        }
        public void SaveToFile (string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Truncate))
            {
                serializer.WriteObject(stream, this);
            }
            Path = filePath;
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
    }
}
