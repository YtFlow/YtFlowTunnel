using System;
using System.Net;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Ipv4Host : IHost
    {
        private static readonly ArgumentException BufferTooSmall = new ArgumentException("Buffer too small", "buffer");
        private readonly uint data;
        public int Size { get => 4; }

        public Ipv4Host (uint dataInNetworkEndianness)
        {
            data = dataInNetworkEndianness;
        }

        public void CopyTo (Span<byte> buffer)
        {
            if (buffer.Length < Size)
            {
                throw BufferTooSmall;
            }

            buffer[0] = (byte)(data & 0xFF);
            buffer[1] = (byte)(data >> 8 & 0xFF);
            buffer[2] = (byte)(data >> 16 & 0xFF);
            buffer[3] = (byte)(data >> 24);
        }

        public override string ToString ()
        {
            return new IPAddress(data).ToString();
        }
    }
}
