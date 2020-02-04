namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Destination
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
    }
}
