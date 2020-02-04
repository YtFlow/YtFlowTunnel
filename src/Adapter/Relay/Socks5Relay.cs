using System;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Destination;
using YtFlow.Tunnel.Adapter.Local;
using YtFlow.Tunnel.Adapter.Remote;
using YtFlow.Tunnel.DNS;

namespace YtFlow.Tunnel.Adapter.Relay
{
    enum Socks5ClientRequestStatus
    {
        None,
        Greeted,
        RequestSent
    }
    internal class Socks5Relay : DirectRelay
    {
        private static readonly byte[] ServerChoicePayload = new byte[] { 5, 0 };
        private static readonly byte[] DummyResponsePayload = new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        private static readonly ArgumentException BadGreetingException = new ArgumentException("Bad socks5 greeting message");
        private static readonly ArgumentException RequestTooShortException = new ArgumentException("Sock5 request is too short");
        private static readonly ArgumentException BadRequestException = new ArgumentException("Bad socks5 request message");
        private static readonly NotImplementedException UnknownTypeException = new NotImplementedException("Unknown socks5 request type");
        private static readonly NotImplementedException Ipv6Exception = new NotImplementedException("IPv6 is not implemented");

        private Socks5ClientRequestStatus clientRequestStatus = Socks5ClientRequestStatus.None;
        private readonly TaskCompletionSource<byte[]> greetingTcs = new TaskCompletionSource<byte[]>();
        private readonly TaskCompletionSource<byte[]> requestTcs = new TaskCompletionSource<byte[]>();
        private Destination.Destination _destination;

        public override Destination.Destination Destination { get => _destination; }

        public Socks5Relay (IRemoteAdapter remoteAdapter) : base(remoteAdapter)
        {

        }

        public static Destination.Destination ParseDestinationFromSocks5Request (byte[] payload)
        {
            if (payload.Length < 7)
            {
                throw RequestTooShortException;
            }
            if (payload[0] != 5)
            {
                throw BadRequestException;
            }
            TransportProtocol protocol;
            switch (payload[1])
            {
                case 1:
                    protocol = TransportProtocol.Tcp;
                    break;
                case 3:
                    protocol = TransportProtocol.Udp;
                    break;
                default:
                    throw UnknownTypeException;
            }
            int destLen;
            IHost host;
            switch (payload[3])
            {
                case 1:
                    destLen = 5;
                    var ipBe = BitConverter.ToUInt32(payload, 4);
                    // Some SOCKS5 clients (e.g. curl) can resolve IP addresses locally.
                    // In this case, we got a fake IP address and need to
                    // convert it back to the corresponding domain name.
                    string domain = DnsProxyServer.Lookup(ipBe);
                    if (domain == null)
                    {
                        host = new Ipv4Host(ipBe);
                    }
                    else
                    {
                        host = new DomainNameHost(domain);
                    }
                    break;
                case 3:
                    var len = payload[4];
                    destLen = len + 2;
                    host = new DomainNameHost(payload.AsSpan(5, len).ToArray());
                    break;
                case 4:
                    throw Ipv6Exception;
                default:
                    throw UnknownTypeException;
            }
            ushort port = (ushort)(payload[3 + destLen] << 8);
            port |= (ushort)(payload[4 + destLen] & 0xFF);
            return new Destination.Destination(host, port, protocol);
        }

        public async override Task Init (ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;

            var greeting = await greetingTcs.Task.ConfigureAwait(false);
            if (greeting.Length < 3 || greeting[0] != 5 || greeting[2] != 0)
            {
                throw BadGreetingException;
            }
            await WriteToLocal(ServerChoicePayload);

            var request = await requestTcs.Task.ConfigureAwait(false);
            _destination = ParseDestinationFromSocks5Request(request);
            ConfirmRecvFromLocal((ushort)request.Length);
            await WriteToLocal(DummyResponsePayload);

            await base.Init(localAdapter).ConfigureAwait(false);
        }

        public override void SendToRemote (byte[] buffer)
        {
            switch (clientRequestStatus)
            {
                case Socks5ClientRequestStatus.None:
                    clientRequestStatus = Socks5ClientRequestStatus.Greeted;
                    greetingTcs.TrySetResult(buffer);
                    ConfirmRecvFromLocal((ushort)buffer.Length);
                    break;
                case Socks5ClientRequestStatus.Greeted:
                    clientRequestStatus = Socks5ClientRequestStatus.RequestSent;
                    requestTcs.TrySetResult(buffer);
                    ConfirmRecvFromLocal((ushort)buffer.Length);
                    break;
                case Socks5ClientRequestStatus.RequestSent:
                    base.SendToRemote(buffer);
                    break;
            }
        }
    }
}
