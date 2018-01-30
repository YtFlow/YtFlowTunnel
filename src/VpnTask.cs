using System.Diagnostics;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace YtFlowTunnel
{
    public sealed class VpnTask: IBackgroundTask
    {
        private static IVpnPlugIn _pluginInstance = null;
        private static object _pluginLocker = new object();
        public static IVpnPlugIn GetPlugin(BackgroundTaskDeferral def)
        {
            if (_pluginInstance == null)
            {
                lock (_pluginLocker)
                {
                    if (_pluginInstance != null) return _pluginInstance;
                    _pluginInstance = new VpnPlugin(def);
                }
            }
            return _pluginInstance;
        }
        public void Run(IBackgroundTaskInstance taskInstance)
        {
            Debug.WriteLine("Running");
            var def = taskInstance.GetDeferral();
            VpnChannel.ProcessEventAsync(GetPlugin(def), taskInstance.TriggerDetails);
        }
    }
}
