using System.Diagnostics;
using System.Threading;
using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Networking.Vpn;

namespace YtFlow.Tunnel
{
    public sealed class VpnTask : IBackgroundTask
    {
        public static IVpnPlugIn GetPlugin (BackgroundTaskDeferral deferral)
        {
            var properties = CoreApplication.Properties;
            if (!properties.TryGetValue("plugin", out var plugin))
            {
#if true
                plugin = new DebugVpnPlugin();
#else
                plugin = new VpnPlugin(deferral);
#endif
                properties["plugin"] = plugin;
            }
            return plugin as IVpnPlugIn;
        }
        public void Run (IBackgroundTaskInstance taskInstance)
        {
            var deferral = taskInstance.GetDeferral();
            var plugin = GetPlugin(deferral);
            VpnChannel.ProcessEventAsync(plugin, taskInstance.TriggerDetails);
        }
    }
}
