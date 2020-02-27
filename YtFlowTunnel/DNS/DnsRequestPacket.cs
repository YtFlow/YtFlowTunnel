using System;
using System.Text;

namespace YtFlow.Tunnel.DNS
{
    internal ref struct DnsRequestPacket
    {
        private static readonly byte[] TTL_IP_LEN = new byte[] { 0, 0, 0, 255, 0, 4 };
        private readonly ReadOnlySpan<byte> queryPacket;
        private readonly int queryStart;
        private readonly int queryEnd;
        public string DomainName { get; }
        public bool IsARecordQuery { get; }

        public unsafe DnsRequestPacket (ReadOnlySpan<byte> packet)
        {
            queryPacket = packet;

            int cursor = 12;
            queryStart = cursor;
            byte length = packet[cursor];
            var sb = new StringBuilder(length * 4);
            do
            {
                var currentSegment = packet.Slice(cursor + 1, length);
                fixed (byte* arr = &currentSegment.GetPinnableReference())
                {
                    sb.Append(Encoding.ASCII.GetString(arr, currentSegment.Length));
                }
                cursor += 1 + length;
                length = packet[cursor];
                if (length > 0)
                {
                    sb.Append('.');
                }
            }
            while (length > 0);

            IsARecordQuery = packet[cursor + 2] == 1;
            queryEnd = cursor + 5;
            DomainName = sb.ToString();
        }

        public int GenerateErrorResponse (ushort flag, Span<byte> outData)
        {
            queryPacket.CopyTo(outData);
            outData[2] = (byte)(flag >> 8);
            outData[3] = (byte)(flag & 0xFF);
            return queryPacket.Length;
        }

        public int GenerateAnswerResponse (uint answerIp, Span<byte> outData)
        {
            var queryLen = queryEnd - queryStart;
            var packet = outData.Slice(0, queryStart + queryLen * 2 + TTL_IP_LEN.Length + 4);
            queryPacket.CopyTo(packet.Slice(0, queryPacket.Length)); // Copy whole packet including a query
            queryPacket.Slice(queryStart, queryLen).CopyTo(packet.Slice(queryEnd)); // Repeat the query domain name
            packet[2] = 0x80; 
            packet[7] = 0x01; // Answer RRs
            TTL_IP_LEN.CopyTo(packet.Slice(queryEnd + queryLen));
            packet[queryEnd + (queryLen++) + TTL_IP_LEN.Length] = (byte)(answerIp >> 24);
            packet[queryEnd + (queryLen++) + TTL_IP_LEN.Length] = (byte)(answerIp >> 16);
            packet[queryEnd + (queryLen++) + TTL_IP_LEN.Length] = (byte)(answerIp >> 8);
            packet[queryEnd + (queryLen++) + TTL_IP_LEN.Length] = (byte)(answerIp & 0xFF);
            return packet.Length;
        }
    }
}
