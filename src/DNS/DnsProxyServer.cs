using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;
using DNS.Server;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Networking;
using Windows.Networking.Sockets;

namespace YtFlow.Tunnel.DNS
{
    public sealed class DnsProxyServer : IDisposable
    {
        private DnsClient client = new DnsClient("10.68.12.236");
        private static ConcurrentDictionary<int, string> lookupTable = new ConcurrentDictionary<int, string>();
        private static ConcurrentDictionary<string, int> rlookupTable = new ConcurrentDictionary<string, int>();

        public void Dispose ()
        {
            lookupTable.Clear();
        }

        private async Task<IList<byte>> Query (
            byte[] payload)
        {
            var req = Request.FromArray(payload);
            Debug.WriteLine("DNS request: " + req.Questions[0].Name);
            //var res = await clireq.Resolve();
            Response res = new Response();
            byte[] ip = new byte[4] { 172, 17, 0, 0 };
            res.Id = req.Id;
            foreach (var q in req.Questions)
            {
                res.Questions.Add(q);
            }
            /*
            if (res.Questions[0].Name.ToString() != "myip.ipip.net" && res.Questions[0].Name.ToString() != "ip.sb")
            {
                try
                {
                    var newres = await client.Lookup(res.Questions[0].Name.ToString(), RecordType.A);
                    var add = newres[0].Address;
                    return new [] { add & 0xFF, add >> 8, add >> 16, add >> 24 }.Select(i => (byte)i).ToList();
                }
                catch (Exception ex)
                {
                    ;
                }
            }*/
            string n = req.Questions[0].Name.ToString();
            if (rlookupTable.TryGetValue(n, out int ipint))
            {
                ip[3] = (byte)(ipint & 0xFF);
                ip[2] = (byte)(0xFF00 & ipint >> 8);
                ResourceRecord answer = ResourceRecord.FromQuestion(req.Questions[0], ip);
                res.AnswerRecords.Add(answer);
            }
            else
            {
                int i = lookupTable.Count();
                lookupTable.TryAdd(i, n);
                rlookupTable.TryAdd(n, i);
                ip[3] = (byte)(i & 0xFF);
                ip[2] = (byte)(0xFF00 & i >> 8);
                ResourceRecord answer = ResourceRecord.FromQuestion(req.Questions[0], ip);
                res.AnswerRecords.Add(answer);
            }
            Debug.WriteLine("DNS request done: " + req.Questions[0].Name);
            //Debug.WriteLine(req);
            return res.ToArray();
        }

        public static string Lookup (int ip)
        {
            lookupTable.TryGetValue(ip, out var ret);
            return ret;
        }

        public IAsyncOperation<IList<byte>> QueryAsync (
            [ReadOnlyArray]
            byte[] payload)
        {
            return Query(payload).AsAsyncOperation();
        }
    }
}
