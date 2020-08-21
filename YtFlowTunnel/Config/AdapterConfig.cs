using System;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
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
        private static DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(AdapterConfig));
        private static Exception adapterTypeNotFoundException = new ArgumentOutOfRangeException("AdapterType", "AdapterType not recognized.");
        public static IAdapterConfig GetConfigFromFilePath (string filePath)
        {
            AdapterConfig baseConfig = null;
            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                baseConfig = serializer.ReadObject(stream) as AdapterConfig;
                if (baseConfig != null)
                {
                    baseConfig.Path = filePath;
                }
            }
            DataContractJsonSerializer subSerializer;
            switch (baseConfig.AdapterType)
            {
                case "shadowsocks":
                    subSerializer = ShadowsocksConfig.serializer;
                    break;
                case "http":
                    subSerializer = HttpConfig.serializer;
                    break;
                case "trojan":
                    subSerializer = TrojanConfig.serializer;
                    break;
                default:
                    throw adapterTypeNotFoundException;
            }

            using (var stream = new FileStream(filePath, FileMode.Open))
            {
                var config = subSerializer.ReadObject(stream) as IAdapterConfig;
                if (config != null)
                {
                    config.Path = filePath;
                }
                return config;
            }
        }
        internal static IRemoteAdapterFactory GetAdapterFactoryFromDefaultFile ()
        {
            var config = GetConfigFromFilePath(GetDefaultConfigFilePath());
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

        static private async Task SaveToFileAsyncImpl<T> (T obj, string filePath, DataContractJsonSerializer serializer) where T : IAdapterConfig
        {
            using (var stream = new MemoryStream())
            {
                serializer.WriteObject(stream, obj);
                stream.Seek(0, SeekOrigin.Begin);
                var file = await StorageFile.GetFileFromPathAsync(filePath);
                await FileIO.WriteBufferAsync(file, stream.GetWindowsRuntimeBuffer(0, (int)stream.Length));
            }
        }

        static internal IAsyncAction SaveToFileAsync<T> (T obj, string filePath, DataContractJsonSerializer serializer) where T : IAdapterConfig
        {
            return SaveToFileAsyncImpl(obj, filePath, serializer).AsAsyncAction();
        }

        public IAsyncAction SaveToFileAsync (string filePath)
        {
            throw new NotImplementedException();
        }

        [DataMember]
        public string AdapterType { get; set; }

        [DataMember]
        public string Name { get; set; }

        [IgnoreDataMember]
        public string Path { get; set; }
    }
}
