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

        public override string ToString ()
        {
            return $"{TransportProtocol}:{Host}:{Port}";
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
