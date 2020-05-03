using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using YtFlow.Tunnel.Config;

namespace YtFlow.Tunnel
{
    sealed class DebugVpnPlugin : IVpnPlugIn
    {
        private DebugVpnContext context = new DebugVpnContext();
        public VpnPluginState State = VpnPluginState.Disconnected;
        public void Connect (VpnChannel channel)
        {
            State = VpnPluginState.Connecting;
            DebugLogger.Logger = s =>
            {
                channel.LogDiagnosticMessage(s);
            };
            DebugLogger.Log("Starting connection to VPN tunnel");
            try
            {
                var transport = new DatagramSocket();
                channel.AssociateTransport(transport, null);

                DebugLogger.Log("Initializing context");
#if !YT_MOCK
                var configPath = AdapterConfig.GetDefaultConfigFilePath();
                if (string.IsNullOrEmpty(configPath))
                {
                    channel.TerminateConnection("Default server configuration not set. Please launch YtFlow app and select a server configuration as default.");
                    return;
                }
                try
                {
                    var config = AdapterConfig.GetConfigFromFilePath(configPath);
                    if (config == null)
                    {
                        channel.TerminateConnection("Could not read server configuration.");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    channel.TerminateConnection("Error reading server configuration: " + ex.ToString());
                    return;
                }
#endif
                DebugLogger.Log("Config read, binding endpoint");
                if (!transport.BindEndpointAsync(new HostName("127.0.0.1"), string.Empty).AsTask().ContinueWith(t =>
                {
                    if (t.IsFaulted || t.IsCanceled)
                    {
                        DebugLogger.Log("Error binding endpoint: " + t.Exception.ToString());
                        return false;
                    }
                    else
                    {
                        DebugLogger.Log("Binded");
                        return true;
                    }
                }).Result)
                {
                    return;
                }
                DebugLogger.Log("Endpoint binded, init context");
                var rport = context.Init(int.Parse(transport.Information.LocalPort)).ToString();
                DebugLogger.Log("Context initialized");
                /* var rport = context.Init(transport.Information.LocalPort, str =>
                {
                    LogLine(str, channel);
                    return null;
                }); */
                DebugLogger.Log("Connecting to local packet processor");
                if (!transport.ConnectAsync(new HostName("127.0.0.1"), rport).AsTask().ContinueWith(t =>
                {
                    if (t.IsFaulted || t.IsCanceled)
                    {
                        channel.TerminateConnection("Error connecting to local packet processor: " + t.Exception.ToString());
                        DebugLogger.Log("Local packet processor connected");
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }).Result)
                {
                    return;
                }
                DebugLogger.Log("Connected to local packet processor");

                VpnRouteAssignment routeScope = new VpnRouteAssignment()
                {
                    ExcludeLocalSubnets = true
                };

                var inclusionRoutes = routeScope.Ipv4InclusionRoutes;
                // DNS server
                inclusionRoutes.Add(new VpnRoute(new HostName("1.1.1.1"), 32));
                // main CIDR
                inclusionRoutes.Add(new VpnRoute(new HostName("11.17.0.0"), 16));
                // proxy
                inclusionRoutes.Add(new VpnRoute(new HostName("172.17.255.0"), 24));

                var assignment = new VpnDomainNameAssignment();
                assignment.DomainNameList.Add(new VpnDomainNameInfo(
                    ".",
                    VpnDomainNameType.Suffix,
                    new[] { new HostName("1.1.1.1") },
                    Array.Empty<HostName>()));

                var now = DateTime.Now;
                DebugLogger.Log("Starting transport");
                channel.StartWithMainTransport(
                new[] { new HostName("192.168.3.1") },
                null,
                null,
                routeScope,
                assignment,
                1500u,
                1512u,
                false,
                transport
                );
                var delta = DateTime.Now - now;
                _ = context.u.SendAsync(new byte[] { 0 }, 1, context.pluginEndpoint);
                DebugLogger.Log($"Transport started in {delta.TotalMilliseconds} ms.");
                State = VpnPluginState.Connected;
            }
            catch (Exception ex)
            {
                var msg = "Error connecting to VPN tunnel: " + ex.ToString();
                channel.TerminateConnection(msg);
                DebugLogger.Log(msg);
                State = VpnPluginState.Disconnected;
            }
        }

        public void Disconnect (VpnChannel channel)
        {
            try
            {
                State = VpnPluginState.Disconnecting;
                DebugLogger.Log("Stopping channel");
                channel.Stop();
                DebugLogger.Log("Stopping context");
                context.Stop();
                DebugLogger.Log("Context stopped");
            }
            catch (Exception ex)
            {
                DebugLogger.Log("Error disconnecting: " + ex.ToString());
            }
            finally
            {
                State = VpnPluginState.Disconnected;
                var _ = DebugLogger.ResetLoggers();
                DebugLogger.initNeeded = null;
            }
        }

        public void GetKeepAlivePayload (VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            /// Not needed
            keepAlivePacket = null;
        }

        public void Encapsulate (VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            try
            {
                uint packetCount = packets.Size;
                var tun = context.tun;
                if (tun == null)
                {
                    return;
                }
                while (packetCount-- > 0)
                {
#if YTLOG_VERBOSE
                    LogLine("Encapsulating " + packets.Size.ToString(), channel);
#endif
                    var packet = packets.RemoveAtBegin();
                    tun.PushPacket(packet.Buffer.ToArray());
                    packets.Append(packet);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log("Error encapsulating packets: " + ex.ToString());
            }
        }

        public void Decapsulate (VpnChannel channel, VpnPacketBuffer encapPacketBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            try
            {
                var reader = context.outPackets?.Reader;
                if (reader == null)
                {
                    return;
                }

                while (reader.TryRead(out var bytes))
                {
                    var encapBuffer = channel.GetVpnReceivePacketBuffer();
                    var encapBuf = encapBuffer.Buffer;
                    bytes.CopyTo(encapBuf);
                    encapBuf.Length = (uint)bytes.Length;
                    decapsulatedPackets.Append(encapBuffer);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log("Error decapsulating packets: " + ex.ToString());
            }
        }
    }

}
