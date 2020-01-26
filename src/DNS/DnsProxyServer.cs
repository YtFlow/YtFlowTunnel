using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;

namespace YtFlow.Tunnel.DNS
{
    internal struct DnsPacket
    {
        private byte[] queryPacket;
        private int queryStart;
        private int queryEnd;
        public DnsPacket (byte[] packet)
        {
            queryPacket = packet;

            ushort id = (ushort)((packet[0] << 8) | packet[1]);
            int cursor = 12;
            queryStart = cursor;
            byte length = packet[cursor];
            var sb = new StringBuilder(length * 4);
            do
            {
                sb.Append(Encoding.ASCII.GetString(packet, cursor + 1, length));
                cursor += 1 + length;
                length = packet[cursor];
                if (length > 0)
                {
                    sb.Append('.');
                }
            }
            while (length > 0);

            IsARecordQuery = packet[cursor + 2] == 1;
            queryEnd = cursor + 1;
            DomainName = sb.ToString();
        }

        public string DomainName { get; }

        public bool IsARecordQuery { get; }

        public byte[] GenerateErrorResponse (ushort flag)
        {
            var queryLen = queryEnd - queryStart;
            byte[] packet = new byte[queryPacket.Length];
            queryPacket.CopyTo(packet.AsSpan());
            packet[2] = (byte)(flag >> 8);
            packet[3] = (byte)(flag & 0xFF); // Not implemented
            return packet;
        }

        public byte[] GenerateAnswerResponse (uint answerIp)
        {
            var queryLen = queryEnd - queryStart;
            byte[] packet = new byte[queryLen * 2 + 30];
            queryPacket.CopyTo(packet.AsSpan());
            queryPacket.AsSpan(queryStart, queryLen + 4).CopyTo(packet.AsSpan(queryEnd + 4));
            packet[2] = 0x80;
            packet[7] = 0x01; // Answer RRs
            packet[packet.Length - 5] = 0x04;
            packet[packet.Length - 4] = (byte)(answerIp >> 24);
            packet[packet.Length - 3] = (byte)(answerIp >> 16 & 0xFF);
            packet[packet.Length - 2] = (byte)(answerIp >> 8 & 0xFF);
            packet[packet.Length - 1] = (byte)(answerIp & 0xFF);
            return packet;
        }
    }
    internal class DnsProxyServer
    {
        private static ConcurrentDictionary<uint, string> lookupTable = new ConcurrentDictionary<uint, string>();
        private static ConcurrentDictionary<string, uint> rlookupTable = new ConcurrentDictionary<string, uint>();

        public void Clear ()
        {
            lookupTable.Clear();
        }

        private async Task<byte[]> Query (
            byte[] payload)
        {
            var dnsPacket = new DnsPacket(payload);
            var n = dnsPacket.DomainName;
            if (!dnsPacket.IsARecordQuery)
            {
                return dnsPacket.GenerateErrorResponse(0x8004); // AAAA query not implemented
            }
            else if (rlookupTable.TryGetValue(n, out var ipint))
            {
                DebugLogger.Log("DNS request done: " + n);
                return dnsPacket.GenerateAnswerResponse(ipint);
            }
            else
            {
                uint ip = (uint)((172 << 24) | (17 << 16) | lookupTable.Count);
                while (!lookupTable.TryAdd(ip, n))
                {
                    ip = (uint)((172 << 24) | (17 << 16) | lookupTable.Count);
                }
                if (!rlookupTable.TryAdd(n, ip))
                {
                    return dnsPacket.GenerateErrorResponse(0x8002); // Server failure
                }
                DebugLogger.Log("DNS request done: " + n);
                return dnsPacket.GenerateAnswerResponse(ip);
            }
        }

        public static string Lookup (uint ip)
        {
            uint value = ip << 24
                | (ip << 8 & 0x00FF0000)
                | (ip >> 8 & 0x0000FF00)
                | ip >> 24;
            lookupTable.TryGetValue(value, out var ret);
            return ret;
        }

        public Task<byte[]> QueryAsync (
            [ReadOnlyArray]
            byte[] payload)
        {
            return Query(payload);
        }
    }
}
