using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DcerpcFindOSInfo
{
    class Program
    {
        static int TIME_OUT = 3000;
        static List<Dictionary<string, Dictionary<string, string>>> RESULT_LIST = new List<Dictionary<string, Dictionary<string, string>>>();
        static int length = 0;

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: SharpDcerpcScan -i <IP Address> [-t <threads>] [-o <Output File>]");
                return;
            }

            string ip = null;
            int threads = 20;
            string output = "log.txt";

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-i" && i + 1 < args.Length)
                {
                    ip = args[i + 1];
                }
                else if (args[i] == "-t" && i + 1 < args.Length)
                {
                    threads = int.Parse(args[i + 1]);
                }
                else if (args[i] == "-o" && i + 1 < args.Length)
                {
                    output = args[i + 1];
                }
            }

            if (ip == null)
            {
                Console.WriteLine("IP Address is required.");
                return;
            }

            Queue<string> ipQueue = new Queue<string>(GetIpList(ip));
            List<Task> tasks = new List<Task>();

            for (int i = 0; i < threads; i++)
            {
                tasks.Add(Task.Run(() => Worker(ipQueue)));
            }

            Task.WaitAll(tasks.ToArray());

            using (StreamWriter writer = new StreamWriter(output, true))
            {
                foreach (var osinfoDict in RESULT_LIST)
                {
                    foreach (var ipInfo in osinfoDict)
                    {
                        writer.WriteLine("[*] " + ipInfo.Key);
                        foreach (var info in ipInfo.Value)
                        {
                            writer.WriteLine("\t[->] " + info.Key + ":" + info.Value);
                        }
                    }
                }
            }
        }

        static List<string> GetIpList(string ip)
        {
            List<string> ipList = new List<string>();
            Func<string, int> iptonum = (x) => x.Split('.').Select(int.Parse).Aggregate(0, (acc, b) => acc * 256 + b);
            Func<int, string> numtoip = (x) => string.Join(".", Enumerable.Range(0, 4).Select(i => (x >> (i * 8)) & 0xFF).Reverse());

            if (ip.Contains('-'))
            {
                var ipRange = ip.Split('-');
                int ipStart = iptonum(ipRange[0]);
                int ipEnd = iptonum(ipRange[1]);
                int ipCount = ipEnd - ipStart;

                if (ipCount >= 0 && ipCount <= 65536)
                {
                    for (int ipNum = ipStart; ipNum <= ipEnd; ipNum++)
                    {
                        ipList.Add(numtoip(ipNum));
                    }
                }
                else
                {
                    Console.WriteLine("-i wrong format");
                }
            }
            else if (ip.EndsWith(".txt"))
            {
                foreach (var line in File.ReadAllLines(ip))
                {
                    ipList.AddRange(GetIpList(line.Trim()));
                }
            }
            else
            {
                var ipSplit = ip.Split('.');
                int net = ipSplit.Length;

                if (net == 2)
                {
                    for (int b = 1; b < 255; b++)
                    {
                        for (int c = 1; c < 255; c++)
                        {
                            ipList.Add($"{ipSplit[0]}.{ipSplit[1]}.{b}.{c}");
                        }
                    }
                }
                else if (net == 3)
                {
                    for (int c = 1; c < 255; c++)
                    {
                        ipList.Add($"{ipSplit[0]}.{ipSplit[1]}.{ipSplit[2]}.{c}");
                    }
                }
                else if (net == 4)
                {
                    ipList.Add(ip);
                }
                else
                {
                    Console.WriteLine("-i wrong format");
                }
            }

            return ipList;
        }

        static void Worker(Queue<string> ipQueue)
        {
            while (ipQueue.Count > 0)
            {
                string ip;
                lock (ipQueue)
                {
                    if (ipQueue.Count == 0) break;
                    ip = ipQueue.Dequeue();
                }

                var result = GetOsInfo(ip);
                if (result != null)
                {
                    lock (RESULT_LIST)
                    {
                        RESULT_LIST.Add(result);
                    }
                }
            }
        }

        static Dictionary<string, Dictionary<string, string>> GetOsInfo(string ip)
        {
            Dictionary<string, string> osinfo = new Dictionary<string, string>
            {
                { "NetBIOS_domain_name", "" },
                { "DNS_domain_name", "" },
                { "DNS_computer_name", "" },
                { "DNS_tree_name", "" }
            };

            using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    sock.ReceiveTimeout = TIME_OUT;
                    sock.SendTimeout = TIME_OUT;
                    sock.Connect(ip, 135);

                    byte[] buffer_v2 = new byte[] {
                        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x78, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x00,
                        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                        0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
                        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
                        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08, 0xa2,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f
                    };

                    sock.Send(buffer_v2);
                    byte[] packet2 = new byte[4096];
                    int received = sock.Receive(packet2);

                    string digit = SendPacket(ip);
                    var osVersionBytes = packet2.Skip(0xa0 - 54 + 10).Take(8).ToArray();
                    int majorVersion = osVersionBytes[0];
                    int minorVersion = osVersionBytes[1];
                    int buildNumber = BitConverter.ToInt16(osVersionBytes, 2);
                    string osVersion = $"Windows Version {majorVersion}.{minorVersion} Build {buildNumber} {digit}";

                    int targetInfoLength = BitConverter.ToInt16(packet2, 0xa0 - 54 + 2);
                    byte[] targetInfoBytes = packet2.Skip(received - targetInfoLength).Take(targetInfoLength - 4).ToArray();

                    Console.WriteLine("[*] " + ip);
                    Console.WriteLine("\t[->] OS_Verison : " + osVersion);

                    foreach (var key in osinfo.Keys.ToList())
                    {
                        osinfo[key] = Attribute_Name(targetInfoBytes);
                        Console.WriteLine("\t[->] " + key + " : " + osinfo[key]);
                    }

                    length = 0;
                    osinfo["OS_Verison"] = osVersion;
                    return new Dictionary<string, Dictionary<string, string>> { { ip, osinfo } };
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                    return null;
                }
            }
        }

        static string SendPacket(string ip)
        {
            using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    sock.ReceiveTimeout = TIME_OUT;
                    sock.SendTimeout = TIME_OUT;
                    sock.Connect(ip, 135);

                    byte[] buffer_v1 = new byte[] {
                        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
                        0x03, 0x00, 0x00, 0x00, 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb,
                        0xef, 0x9c, 0xcc, 0x36, 0x01, 0x00, 0x00, 0x00
                    };

                    sock.Send(buffer_v1);
                    byte[] packet1 = new byte[1024];
                    sock.Receive(packet1);

                    if (ContainsSequence(packet1, new byte[] { 0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49, 0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36 }))
                    {
                        return "x64";
                    }
                    return "x86";
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                    return "-1";
                }
            }
        }

        static bool ContainsSequence(byte[] array, byte[] sequence)
        {
            for (int i = 0; i <= array.Length - sequence.Length; i++)
            {
                if (array.Skip(i).Take(sequence.Length).SequenceEqual(sequence))
                {
                    return true;
                }
            }
            return false;
        }

        static string Attribute_Name(byte[] targetInfoBytes)
        {
            if (length + 4 > targetInfoBytes.Length) return "";
            int attNameLength = BitConverter.ToInt16(targetInfoBytes, length + 2);
            if (length + 4 + attNameLength > targetInfoBytes.Length) return "";
            string attName = Encoding.Unicode.GetString(targetInfoBytes, length + 4, attNameLength).Replace("\x00", "");
            length += 4 + attNameLength;
            return attName;
        }
    }
}
