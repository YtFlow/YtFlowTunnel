using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
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
        private static Dictionary<uint, string> lookupTable = new Dictionary<uint, string>();
        private static Dictionary<string, uint> rlookupTable = new Dictionary<string, uint>();
        private static SemaphoreSlim dnsLock = new SemaphoreSlim(1, 1);

        public void Clear ()
        {
            lookupTable.Clear();
        }

        private async Task<byte[]> RealQueryAsync (
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
                lookupTable[ip] = n;
                rlookupTable[n] = ip;
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

        public async Task<byte[]> QueryAsync (
            [ReadOnlyArray]
            byte[] payload)
        {
            await dnsLock.WaitAsync().ConfigureAwait(false);
            try
            {
                return await RealQueryAsync(payload).ConfigureAwait(false);
            }
            finally
            {
                dnsLock.Release();
            }
        }
    }
}
