using YtFlow.Tunnel.Adapter.Remote;

namespace YtFlow.Tunnel.Adapter.Factory
{
    internal interface IRemoteAdapterFactory
    {
        IRemoteAdapter CreateAdapter ();
    }
}
