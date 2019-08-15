using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Networking.Vpn;

namespace YtFlow.Tunnel
{
    public sealed class VpnTask : IBackgroundTask
    {
        public static IVpnPlugIn GetPlugin ()
        {
            var properties = CoreApplication.Properties;
            if (!properties.TryGetValue("plugin", out var plugin))
            {
#if true
                plugin = new DebugVpnPlugin();
#else
                plugin = new VpnPlugin();
#endif
                properties["plugin"] = plugin;
            }
            return plugin as IVpnPlugIn;
        }
        public void Run (IBackgroundTaskInstance taskInstance)
        {
            VpnChannel.ProcessEventAsync(GetPlugin(), taskInstance.TriggerDetails);
        }
    }
}
