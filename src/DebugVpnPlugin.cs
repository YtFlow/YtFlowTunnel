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

                DebugVpnContext context = VpnTask.GetContext();
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
                if (!transport.BindEndpointAsync(new HostName("127.0.0.1"), "9007").AsTask().ContinueWith(t =>
                {
                    if (t.IsCompleted)
                    {
                        DebugLogger.Log("Binded");
                        return true;
                    }
                    else if (t.IsFaulted)
                    {
                        DebugLogger.Log("Error binding endpoint: " + t.Exception.ToString());
                    }
                    return false;
                }).Result)
                {
                    return;
                }
                DebugLogger.Log("Endpoint binded, init context");
                context.Init();
                DebugLogger.Log("Context initialized");
                /* var rport = context.Init(transport.Information.LocalPort, str =>
                {
                    LogLine(str, channel);
                    return null;
                }); */
                var rport = "9008";
                DebugLogger.Log("Connecting to local packet processor");
                if (!transport.ConnectAsync(new HostName("127.0.0.1"), rport).AsTask().ContinueWith(t =>
                {
                    if (t.IsCompleted)
                    {
                        DebugLogger.Log("Local packet processor connected");
                        return true;
                    }
                    else if (t.IsFaulted)
                    {
                        channel.TerminateConnection("Error connecting to local packet processor: " + t.Exception.ToString());
                    }
                    return false;
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
                // myip.ipip.net
                //inclusionRoutes.Add(new VpnRoute(new HostName("36.99.18.134"), 32));
                // qzworld.net
                //inclusionRoutes.Add(new VpnRoute(new HostName("188.166.248.242"), 32));
                // DNS server
                inclusionRoutes.Add(new VpnRoute(new HostName("1.1.1.1"), 32));
                // main CIDR
                inclusionRoutes.Add(new VpnRoute(new HostName("172.17.0.0"), 16));

                var assignment = new VpnDomainNameAssignment();
                var dnsServers = new[]
                {
                    // DNS servers
                    new HostName("1.1.1.1"),
                };
                assignment.DomainNameList.Add(new VpnDomainNameInfo(".", VpnDomainNameType.Suffix, dnsServers, new HostName[] { }));

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
                DebugLogger.Log($"Transport started in {delta.TotalMilliseconds} ms.");
                State = VpnPluginState.Connected;
            }
            catch (Exception ex)
            {
                channel.TerminateConnection("Error connecting to VPN tunnel: " + ex.ToString());
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
                VpnTask.GetContext()?.Stop();
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
            //// Not needed
            keepAlivePacket = new VpnPacketBuffer(null, 0, 0);
        }

        public void Encapsulate (VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            try
            {
                uint packetCount;
                while ((packetCount = packets.Size) > 0)
                {
                    while (packetCount-- > 0)
                    {
#if YTLOG_VERBOSE
                        LogLine("Encapsulating " + packets.Size.ToString(), channel);
#endif
                        var packet = packets.RemoveAtBegin();
                        encapulatedPackets.Append(packet);
                    }
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
                var vpnPacketBuffer = channel.GetVpnReceivePacketBuffer();
                // Avoid duplicated calls to buffer accessors
                var vpnBuffer = vpnPacketBuffer.Buffer;
                var encapBuf = encapPacketBuffer.Buffer;
#if YTLOG_VERBOSE
                LogLine("Decapsulating one packet", channel);
#endif
                if (encapBuf.Length > vpnBuffer.Capacity)
                {
                    //Drop larger packets.
                    DebugLogger.Log("Dropped an oversized packet");
                    return;
                }

                encapBuf.CopyTo(vpnBuffer);
                vpnBuffer.Length = encapBuf.Length;
                decapsulatedPackets.Append(vpnPacketBuffer);
                // LogLine("Decapsulated one packet", channel);
            }
            catch (Exception ex)
            {
                DebugLogger.Log("Error decapsulating packets: " + ex.ToString());
            }
        }
    }

}
