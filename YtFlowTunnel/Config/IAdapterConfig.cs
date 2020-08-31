namespace YtFlow.Tunnel.Config
{
    public interface IAdapterConfig
    {
        // set accessor is for deserialization
        string AdapterType { get; set; }
        string Name { get; set; }
        string Path { get; set; }
    }
}
