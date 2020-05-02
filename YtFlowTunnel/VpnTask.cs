using System;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace YtFlow.Tunnel
{
    public sealed class VpnTask : IBackgroundTask
    {
        internal static DebugVpnPlugin Plugin = new DebugVpnPlugin();
        public void Run (IBackgroundTaskInstance taskInstance)
        {
            var initDebugSocketNeeded = DebugLogger.InitNeeded();
            if (initDebugSocketNeeded)
            {
                try
                {
                    var _ = DebugLogger.InitDebugSocket();
                }
                catch (Exception) { }
            }
            VpnChannel.ProcessEventAsync(Plugin, taskInstance.TriggerDetails);
            DebugLogger.Log("VPN Background task finished");
        }
    }
}
