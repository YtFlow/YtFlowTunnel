using System.Diagnostics;
using System.Threading;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace YtFlow.Tunnel
{
    public sealed class VpnTask : IBackgroundTask
    {
        private static IVpnPlugIn _pluginInstance = null;
        public static IVpnPlugIn GetPlugin ()
        {
            if (_pluginInstance != null) return _pluginInstance;
#if true
            _pluginInstance = new DebugVpnPlugin();
#else
            _pluginInstance = new VpnPlugin();
#endif
            return _pluginInstance;
        }
        public void Run (IBackgroundTaskInstance taskInstance)
        {
            var plugin = GetPlugin();
            VpnChannel.ProcessEventAsync(plugin, taskInstance.TriggerDetails);
        }
    }
}
