using System;
using System.Net;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Ipv4Host : IHost, IEquatable<Ipv4Host>
    {
        private static readonly ArgumentException BufferTooSmall = new ArgumentException("Buffer too small", "buffer");
        public readonly uint Data;
        public int Size { get => 4; }

        public Ipv4Host (uint dataInNetworkEndianness)
        {
            Data = dataInNetworkEndianness;
        }

        public void CopyTo (Span<byte> buffer)
        {
            if (buffer.Length < Size)
            {
                throw BufferTooSmall;
            }

            buffer[0] = (byte)(Data & 0xFF);
            buffer[1] = (byte)(Data >> 8 & 0xFF);
            buffer[2] = (byte)(Data >> 16 & 0xFF);
            buffer[3] = (byte)(Data >> 24);
        }

        public override string ToString ()
        {
            return new IPAddress(Data).ToString();
        }

        public override bool Equals (object obj)
        {
            return obj is Ipv4Host host && Equals(host);
        }

        public bool Equals (Ipv4Host other)
        {
            return Data == other.Data;
        }

        public override int GetHashCode ()
        {
            return -301143667 + Data.GetHashCode();
        }

        public static bool operator == (Ipv4Host left, Ipv4Host right)
        {
            return left.Equals(right);
        }

        public static bool operator != (Ipv4Host left, Ipv4Host right)
        {
            return !(left == right);
        }
    }
}
