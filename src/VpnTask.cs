using Windows.ApplicationModel.Background;
using Windows.ApplicationModel.Core;
using Windows.Networking.Vpn;

namespace YtFlow.Tunnel
{
    public sealed class VpnTask : IBackgroundTask
    {
        internal static T GetSharedObject<T> (string key) where T : new()
        {
            var properties = CoreApplication.Properties;
            if (!properties.TryGetValue(key, out var obj))
            {
                obj = new T();
                properties[key] = obj;
            }
            return (T)obj;
        }
        internal static void ClearSharedObject(string key)
        {
            CoreApplication.Properties.Remove(key);
        }
        internal static DebugVpnPlugin GetPlugin () => GetSharedObject<DebugVpnPlugin>("plugin");
        internal static DebugVpnContext GetContext () => GetSharedObject<DebugVpnContext>("context");
        internal static void ClearPlugin() => ClearSharedObject("plugin");
        internal static void ClearContext() => ClearSharedObject("context");
        internal static BackgroundTaskDeferral deferral;
        public void Run (IBackgroundTaskInstance taskInstance)
        {
            deferral?.Complete();
            deferral = null;
            // deferral = taskInstance.GetDeferral();
            VpnChannel.ProcessEventAsync(GetPlugin(), taskInstance.TriggerDetails);
        }
    }
}
