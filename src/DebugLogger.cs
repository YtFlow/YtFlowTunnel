using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage;

namespace YtFlow.Tunnel
{
    public static class DebugLogger
    {
        internal static Action<string> Logger { get; set; } = (_) => { };
        internal static DatagramSocket debugSocket;
        internal static bool? initNeeded;
        private const string DEBUG_HOST_CONFIG = "debug_host";
        private const string DEBUG_PORT_CONFIG = "debug_port";
        internal static readonly IPropertySet Settings = ApplicationData.Current.LocalSettings.Values;

        private static async Task RealSetDebugSocketAddr (string host, string port)
        {
            if (Settings.ContainsKey(DEBUG_HOST_CONFIG))
            {
                Settings[DEBUG_HOST_CONFIG] = host;
            }
            else
            {
                Settings.Add(DEBUG_HOST_CONFIG, host);
            }
            if (Settings.ContainsKey(DEBUG_PORT_CONFIG))
            {
                Settings[DEBUG_PORT_CONFIG] = port;
            }
            else
            {
                Settings.Add(DEBUG_PORT_CONFIG, port);
            }
            await ResetLoggers();
            await InitDebugSocket();
        }

        public static string RealGetDebugSocketHost ()
        {
            return Settings[DEBUG_HOST_CONFIG] as string;
        }

        public static string RealGetDebugSocketPort ()
        {
            return Settings[DEBUG_PORT_CONFIG] as string;
        }

        public static IAsyncAction SetDebugSocketAddr (string host, string port)
        {
            return RealSetDebugSocketAddr(host, port).AsAsyncAction();
        }

        public static bool IsDebugAddrSet ()
        {
            return Settings.TryGetValue(DEBUG_HOST_CONFIG, out var host) && host is string
                && Settings.TryGetValue(DEBUG_PORT_CONFIG, out var port) && port is string;
        }

        private static async Task RealInitDebugSocket ()
        {
            if (debugSocket != null) return;
            if (!(Settings.TryGetValue(DEBUG_HOST_CONFIG, out var hostObj) && hostObj is string host
                && Settings.TryGetValue(DEBUG_PORT_CONFIG, out var portObj) && portObj is string port))
            {
                return;
            }
            debugSocket = new DatagramSocket();
            await debugSocket.ConnectAsync(new HostName(host), port);
            await RealLog("Debug socket init\r\n");
        }

        public static IAsyncAction InitDebugSocket ()
        {
            return RealInitDebugSocket().ContinueWith(t => { }).AsAsyncAction();
        }

        public static bool InitNeeded ()
        {
            if (initNeeded is bool realInitNeeded)
            {
                return realInitNeeded;
            }
            realInitNeeded = debugSocket != null && IsDebugAddrSet();
            initNeeded = realInitNeeded;
            return realInitNeeded;
        }

        private static async Task RealResetLoggers ()
        {
            Logger = (_) => { };
            var localDebugSocket = debugSocket;
            if (localDebugSocket == null)
            {
                return;
            }
            try
            {
                await RealLog("Disposing debug socket\r\n");
                await localDebugSocket.CancelIOAsync();
            }
            catch (Exception) { }
            try
            {
                localDebugSocket.Dispose();
            }
            finally
            {
                debugSocket = null;
            }
        }

        public static IAsyncAction ResetLoggers ()
        {
            return RealResetLoggers().AsAsyncAction();
        }

        private static async Task RealLogPacketWithTimestamp (byte[] b)
        {
#if YTLOG_VERBOSE
            var socket = debugSocket;
            if (socket == null) return;
            var date = DateTime.Now.ToString("HH:mm:ss.fff\r\n");
            var sb = new StringBuilder(b.Length * 3 + 11 + 16);
            sb.Append(date);
            sb.Append("000000 ");
            foreach (var by in b)
            {
                sb.AppendFormat("{0:x2} ", by);
            }
            sb.Append("\r\n");
            try
            {
                await socket.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(sb.ToString()).AsBuffer());
                await socket.OutputStream.FlushAsync();
            }
            catch (Exception)
            {
            }
#else
            return;
#endif
        }

        internal static Task LogPacketWithTimestamp (byte[] b)
        {
            if (debugSocket == null)
            {
                return Task.CompletedTask;
            }
            return RealLogPacketWithTimestamp(b);
        }

        private static Task RealLog (string message)
        {
            try
            {
                Logger(message);
            }
            catch (Exception) { }
            if (debugSocket == null)
            {
                return Task.CompletedTask;
            }
            return debugSocket.OutputStream?.WriteAsync(Encoding.UTF8.GetBytes(message).AsBuffer())?.AsTask() ?? Task.CompletedTask;
        }

        public static void Log (string message)
        {
            RealLog(message + "\r\n").ContinueWith(t => { });
        }
    }
}
