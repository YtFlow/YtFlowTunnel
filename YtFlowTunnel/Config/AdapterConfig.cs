using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Storage;
using YtFlow.Tunnel.Adapter.Factory;

namespace YtFlow.Tunnel.Config
{
    [DataContract]
    public sealed class AdapterConfig : IAdapterConfig
    {
        private const string DEFAULT_CONFIG_PATH_KEY = "ytflow.tunnel.config.default_path";
        // private static DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(AdapterConfig));
        private static readonly JsonSerializer serializer = JsonSerializer.CreateDefault();
        private static readonly Exception adapterTypeNotFoundException = new ArgumentOutOfRangeException("AdapterType", "AdapterType not recognized.");
        public static IAsyncOperation<IAdapterConfig> GetConfigFromFilePath (string filePath)
        {
            return GetConfigFromFilePathImpl(filePath).AsAsyncOperation();
        }
        internal static async Task<IAdapterConfig> GetConfigFromFilePathImpl (string filePath)
        {
            string fileContent = await PathIO.ReadTextAsync(filePath);
            var json = JObject.Parse(fileContent);
            var adapterType = json.GetValue(nameof(IAdapterConfig.AdapterType)).Value<string>();
            var reader = json.CreateReader();
            IAdapterConfig config;
            switch (adapterType)
            {
                case "shadowsocks":
                    config = new ShadowsocksConfig();
                    break;
                case "http":
                    config = new HttpConfig();
                    break;
                case "trojan":
                    config = new TrojanConfig();
                    break;
                default:
                    throw adapterTypeNotFoundException;
            }
            serializer.Populate(reader, config);
            config.Path = filePath;
            return config;
        }
        internal static async Task<IRemoteAdapterFactory> GetAdapterFactoryFromDefaultFile ()
        {
            var config = await GetConfigFromFilePathImpl(GetDefaultConfigFilePath());
            switch (config)
            {
                case ShadowsocksConfig ssConfig:
                    return new ShadowsocksFactory(ssConfig);
                case HttpConfig htConfig:
                    return new HttpFactory(htConfig);
                case TrojanConfig tjConfig:
                    return new TrojanFactory(tjConfig);
                default:
                    throw adapterTypeNotFoundException;
            }
        }
        public static string GetDefaultConfigFilePath ()
        {
            ApplicationData.Current.LocalSettings.Values.TryGetValue(DEFAULT_CONFIG_PATH_KEY, out var ret);
            return ret as string;
        }
        public static void SetDefaultConfigFilePath (string configFilePath)
        {
            ApplicationData.Current.LocalSettings.Values[DEFAULT_CONFIG_PATH_KEY] = configFilePath;
        }
        public static void ClearDefaultConfigFilePath ()
        {
            ApplicationData.Current.LocalSettings.Values.Remove(DEFAULT_CONFIG_PATH_KEY);
        }

        [DataMember]
        public string AdapterType { get; set; }

        [DataMember]
        public string Name { get; set; }

        [IgnoreDataMember]
        public string Path { get; set; }
    }
}
