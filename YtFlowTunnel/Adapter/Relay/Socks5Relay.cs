using System;
using System.Threading;
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
        private static readonly byte[] UdpResponseHeaderPrefix = new byte[] { 0, 0, 0 };
        private static readonly ArgumentException BadGreetingException = new ArgumentException("Bad socks5 greeting message");
        private static readonly ArgumentException RequestTooShortException = new ArgumentException("Sock5 request is too short");
        private static readonly ArgumentException BadRequestException = new ArgumentException("Bad socks5 request message");
        private static readonly NotImplementedException UnknownTypeException = new NotImplementedException("Unknown socks5 request type");

        private Socks5ClientRequestStatus clientRequestStatus = Socks5ClientRequestStatus.None;
        private readonly TaskCompletionSource<byte[]> greetingTcs = new TaskCompletionSource<byte[]>();
        private readonly TaskCompletionSource<byte[]> requestTcs = new TaskCompletionSource<byte[]>();
        private byte[] preparedUdpResponseHeader;

        public Socks5Relay (IRemoteAdapter remoteAdapter) : base(remoteAdapter)
        {
        }

        public static Destination.Destination ParseDestinationFromRequest (ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 8)
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
            if (Adapter.Destination.Destination.TryParseSocks5StyleAddress(payload.Slice(3), out Destination.Destination destination, protocol) == 0)
            {
                throw RequestTooShortException;
            }

            // Some SOCKS5 clients (e.g. curl) can resolve IP addresses locally.
            // In this case, we got a fake IP address and need to
            // convert it back to the corresponding domain name.
            switch (destination.Host)
            {
                case Ipv4Host ipv4:
                    destination = new Destination.Destination(DnsProxyServer.TryLookup(ipv4.Data), destination.Port, protocol);
                    break;
            }
            return destination;
        }

        public static int ParseDestinationFromUdpPayload (ReadOnlySpan<byte> payload, out Destination.Destination destination)
        {
            if (payload.Length < 9)
            {
                destination = default;
                return 0;
            }
            if (payload[2] != 0)
            {
                // FRAG is not supported
            }
            var len = 3;
            len += Adapter.Destination.Destination.TryParseSocks5StyleAddress(payload.Slice(3), out destination, TransportProtocol.Udp);
            if (len == 0)
            {
                destination = default;
                return 0;
            }
            return len;
        }

        public int FillDestinationIntoSocks5UdpPayload (Span<byte> data)
        {
            if (preparedUdpResponseHeader != null)
            {
                preparedUdpResponseHeader.CopyTo(data);
                return preparedUdpResponseHeader.Length;
            }

            int len = 0;
            UdpResponseHeaderPrefix.CopyTo(data);
            len += UdpResponseHeaderPrefix.Length;
            // TODO: Fill destination with domain name as host?
            len += Destination.FillSocks5StyleAddress(data.Slice(len));
            preparedUdpResponseHeader = new byte[len];
            data.Slice(0, len).CopyTo(preparedUdpResponseHeader);
            return len;
        }

        public async override ValueTask Init (ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;

            var greeting = await greetingTcs.Task.ConfigureAwait(false);
            if (greeting.Length < 3 || greeting[0] != 5 || greeting[2] != 0)
            {
                throw BadGreetingException;
            }
            await WriteToLocal(ServerChoicePayload);

            var request = await requestTcs.Task.ConfigureAwait(false);
            Destination = ParseDestinationFromRequest(request);
            if (Destination.TransportProtocol == TransportProtocol.Udp)
            {
                throw UnknownTypeException;
            }
            await WriteToLocal(DummyResponsePayload);

            await base.Init(localAdapter).ConfigureAwait(false);
        }

        public override Task StartRecv (CancellationToken cancellationToken = default)
        {
            switch (Destination.TransportProtocol)
            {
                case TransportProtocol.Tcp:
                    return base.StartRecv(cancellationToken);
            }
            throw new NotImplementedException();
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
                    switch (Destination.TransportProtocol)
                    {
                        case TransportProtocol.Tcp:
                            base.SendToRemote(buffer);
                            break;
                    }
                    break;
            }
        }
    }
}
