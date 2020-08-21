using Windows.Foundation;

namespace YtFlow.Tunnel.Config
{
    public interface IAdapterConfig
    {
        IAsyncAction SaveToFileAsync (string filePath);
        // set accessor is for deserialization
        string AdapterType { get; set; }
        string Name { get; set; }
        string Path { get; set; }
    }
}
