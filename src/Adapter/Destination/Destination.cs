using System;
using System.Collections.Generic;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Destination : IEquatable<Destination>
    {
        public IHost Host { get; }
        public ushort Port { get; }
        public TransportProtocol TransportProtocol { get; }

        public Destination (IHost host, ushort port, TransportProtocol transportProtocol)
        {
            Host = host;
            Port = port;
            TransportProtocol = transportProtocol;
        }

        /// <summary>
        /// Try to parse SOCKS5-style address structure. Returns 0 when more data is needed.
        /// </summary>
        /// <param name="data">Input data</param>
        /// <param name="destination">Parsed destination structure</param>
        /// <param name="transportProtocol"></param>
        /// <returns>Length of actual address. 0 when more data is needed.</returns>
        public static int TryParseSocks5StyleAddress (ReadOnlySpan<byte> data, out Destination destination, TransportProtocol transportProtocol)
        {
            if (data.Length < 7)
            {
                destination = default;
                return 0;
            }
            var len = 0;
            IHost host;
            switch (data[len++])
            {
                case 1:
                    var ipBe = BitConverter.ToUInt32(data.Slice(len, 4).ToArray(), 0);
                    host = new Ipv4Host(ipBe);
                    len += 4;
                    break;
                case 3:
                    var domainLen = data[len++];
                    if (data.Length < domainLen + 4)
                    {
                        destination = default;
                        return 0;
                    }
                    host = new DomainNameHost(data.Slice(len, domainLen).ToArray());
                    len += domainLen;
                    break;
                default:
                    // TODO: IPv6
                    throw new NotImplementedException();
            }
            ushort port = (ushort)(data[len] << 8 | data[len + 1] & 0xFF);
            len += 2;
            destination = new Destination(host, port, transportProtocol);
            return len;
        }

        public override string ToString ()
        {
            return $"{TransportProtocol}:{Host}:{Port}";
        }

        public int FillSocks5StyleAddress (Span<byte> data)
        {
            int offset = Host.Size + 3;
            switch (Host)
            {
                case DomainNameHost domainHost:
                    offset++;
                    data[0] = 0x03;
                    data[1] = (byte)domainHost.Size;
                    domainHost.CopyTo(data.Slice(2));
                    break;
                case Ipv4Host ipv4:
                    data[0] = 0x01;
                    ipv4.CopyTo(data.Slice(1, 4));
                    break;
                case Ipv6Host ipv6:
                    data[0] = 0x04;
                    ipv6.CopyTo(data.Slice(1, 16));
                    break;
            }
            data[offset - 2] = (byte)(Port >> 8);
            data[offset - 1] = (byte)(Port & 0xFF);
            return offset;
        }

        public override bool Equals (object obj)
        {
            return obj is Destination destination && Equals(destination);
        }

        public bool Equals (Destination other)
        {
            return EqualityComparer<IHost>.Default.Equals(Host, other.Host) &&
                   Port == other.Port &&
                   TransportProtocol == other.TransportProtocol;
        }

        public override int GetHashCode ()
        {
            var hashCode = 187540647;
            hashCode = hashCode * -1521134295 + EqualityComparer<IHost>.Default.GetHashCode(Host);
            hashCode = hashCode * -1521134295 + Port.GetHashCode();
            hashCode = hashCode * -1521134295 + TransportProtocol.GetHashCode();
            return hashCode;
        }

        public static bool operator == (Destination left, Destination right)
        {
            return left.Equals(right);
        }

        public static bool operator != (Destination left, Destination right)
        {
            return !(left == right);
        }
    }
}
