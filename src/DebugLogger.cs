using System;

namespace YtFlow.Tunnel
{
    public static class DebugLogger
    {
        internal static Action<string> Logger { get; set; } = (_) => { };
        public static void Log (string message)
        {
            Logger(message);
        }
    }
}
