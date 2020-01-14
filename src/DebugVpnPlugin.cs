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
        private VpnChannel cachedChannelForLogging;
        private void LogLine (string text, VpnChannel channel)
        {
            //Debug.WriteLine(text);
            channel.LogDiagnosticMessage(text);
            cachedChannelForLogging = channel;
        }
        public void TryLogLine (string text)
        {
            cachedChannelForLogging?.LogDiagnosticMessage(text);
        }
        public void Connect (VpnChannel channel)
        {
            if (State != VpnPluginState.Disconnected)
            {
                LogLine("Attempted to connect at wrong state: " + State.ToString(), channel);
                return;
            }
            State = VpnPluginState.Connecting;
            LogLine("Connecting", channel);
            DebugLogger.Logger = (s) => cachedChannelForLogging.LogDiagnosticMessage(s);
            try
            {
                var transport = new DatagramSocket();
                channel.AssociateTransport(transport, null);

                DebugVpnContext context = VpnTask.GetContext();
                LogLine("Initializing context", channel);
#if !YT_MOCK
                var configPath = AdapterConfig.GetDefaultConfigFilePath();
                if (string.IsNullOrEmpty(configPath))
                {
                    channel.TerminateConnection("Config not set");
                    return;
                }
                try
                {
                    var config = AdapterConfig.GetConfigFromFilePath(configPath);
                    if (config == null)
                    {
                        throw new Exception("Cannot read config file.");
                    }
                }
                catch (Exception ex)
                {
                    channel.TerminateConnection("Error reading config file:" + ex.Message);
                    return;
                }
#endif
                transport.BindEndpointAsync(new HostName("127.0.0.1"), "9007").AsTask().ContinueWith(t =>
                {
                    if (t.IsCompleted)
                    {
                        LogLine("Binded", channel);
                    }
                    else if (t.IsFaulted)
                    {
                        channel.LogDiagnosticMessage("Error binding:");
                        channel.LogDiagnosticMessage(t.Exception.Message);
                        channel.LogDiagnosticMessage(t.Exception.StackTrace);
                    }
                }).Wait();
                context.Init();
                /* var rport = context.Init(transport.Information.LocalPort, str =>
                {
                    LogLine(str, channel);
                    return null;
                }); */
                var rport = "9008";
                transport.ConnectAsync(new HostName("127.0.0.1"), rport).AsTask().ContinueWith(t =>
                {
                    if (t.IsCompleted)
                    {
                        LogLine("r Connected", channel);
                    }
                    else if (t.IsFaulted)
                    {
                        channel.LogDiagnosticMessage("Error connecting r:");
                        channel.LogDiagnosticMessage(t.Exception.Message);
                        channel.LogDiagnosticMessage(t.Exception.StackTrace);
                    }
                });

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
                LogLine("Starting transport", channel);
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
                LogLine($"Finished starting transport in {delta.TotalMilliseconds} ms.", channel);
                LogLine("Connected", channel);
                State = VpnPluginState.Connected;
            }
            catch (Exception ex)
            {
                LogLine("Error connecting", channel);
                LogLine(ex.Message, channel);
                LogLine(ex.StackTrace, channel);
                channel.TerminateConnection("Cannot connect to local tunnel");
                State = VpnPluginState.Disconnected;
            }
        }

        public void Disconnect (VpnChannel channel)
        {
            try
            {
                State = VpnPluginState.Disconnecting;
                LogLine("Stopping channel", channel);
                channel.Stop();
                LogLine("Disconnecting context", channel);
                VpnTask.GetContext()?.Stop();
                LogLine("Disconnected", channel);
            }
            catch (Exception ex)
            {
                LogLine(ex.Message, channel);
                LogLine(ex.StackTrace, channel);
            }
            finally
            {
                State = VpnPluginState.Disconnected;
                VpnTask.ClearPlugin();
                VpnTask.ClearContext();
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
                while (packets.Size > 0)
                {
#if YTLOG_VERBOSE
                    LogLine("Encapsulating " + packets.Size.ToString(), channel);
#endif
                    var packet = packets.RemoveAtBegin();
                    encapulatedPackets.Append(packet);
                    //LogLine("Encapsulated one packet", channel);
                }
            }
            catch (Exception ex)
            {
                LogLine(ex.Message, channel);
            }
        }

        public void Decapsulate (VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            try
            {
                var buf = channel.GetVpnReceivePacketBuffer();
#if YTLOG_VERBOSE
                LogLine("Decapsulating one packet", channel);
#endif
                if (encapBuffer.Buffer.Length > buf.Buffer.Capacity)
                {
                    LogLine("Dropped one packet", channel);
                    //Drop larger packets.
                    return;
                }

                encapBuffer.Buffer.CopyTo(buf.Buffer);
                buf.Buffer.Length = encapBuffer.Buffer.Length;
                decapsulatedPackets.Append(buf);
                // LogLine("Decapsulated one packet", channel);
            }
            catch (Exception ex)
            {
                LogLine(ex.Message, channel);
                LogLine(ex.StackTrace, channel);
            }

        }
    }

}
