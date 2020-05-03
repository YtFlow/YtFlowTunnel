using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Destination;

namespace YtFlow.Tunnel.DNS
{
    internal class DnsProxyServer
    {
        private static readonly Dictionary<uint, string> lookupTable = new Dictionary<uint, string>();
        private static readonly Dictionary<string, uint> rlookupTable = new Dictionary<string, uint>();
        private static SemaphoreSlim dnsLock = new SemaphoreSlim(1, 1);

        public static void Clear ()
        {
            lookupTable.Clear();
        }

        private static int RealQuery (
            ReadOnlySpan<byte> payload, Span<byte> outData)
        {
            var dnsPacket = new DnsRequestPacket(payload);
            var n = dnsPacket.DomainName;
            if (!dnsPacket.IsARecordQuery)
            {
                return dnsPacket.GenerateErrorResponse(0x8004, outData); // AAAA query not implemented
            }
            else if (rlookupTable.TryGetValue(n, out var ipint))
            {
                DebugLogger.Log("DNS request done: " + n);
                return dnsPacket.GenerateAnswerResponse(ipint, outData);
            }
            else
            {
                uint ip = (uint)((11 << 24) | (17 << 16) | lookupTable.Count);
                lookupTable[ip] = n;
                rlookupTable[n] = ip;
                DebugLogger.Log("DNS request done: " + n);
                return dnsPacket.GenerateAnswerResponse(ip, outData);
            }
        }

        public static string Lookup (uint ipInNetworkEndianness)
        {
            var value = (uint)IPAddress.NetworkToHostOrder((int)ipInNetworkEndianness);
            lookupTable.TryGetValue(value, out var ret);
            return ret;
        }

        public static IHost TryLookup (uint ipInNetworkEndianness)
        {
            var domain = Lookup(ipInNetworkEndianness);
            if (domain == null)
            {
                return new Ipv4Host(ipInNetworkEndianness);
            }
            else
            {
                return new DomainNameHost(domain);
            }
        }

        internal static bool ReverseQuery (string domain, out Ipv4Host host)
        {
            if (rlookupTable.TryGetValue(domain, out var value))
            {
                // TODO: what if the IP address falls in fake IP range?
                host = new Ipv4Host((uint)IPAddress.HostToNetworkOrder((int)value));
                return true;
            }
            else
            {
                host = default;
                return false;
            }
        }

        public static async Task<int> QueryAsync (
            [ReadOnlyArray]
            Memory<byte> payload, Memory<byte> outData)
        {
            await dnsLock.WaitAsync().ConfigureAwait(false);
            try
            {
                return RealQuery(payload.Span, outData.Span);
            }
            finally
            {
                dnsLock.Release();
            }
        }
    }
}
