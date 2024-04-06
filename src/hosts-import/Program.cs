using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Enumeration;
using System.Security.Cryptography;
using System.Xml;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace hosts_import
{
    class HostFile
    {
        List<string> HostsList;
        string hostsfilename;
        public void Read(string filename)
        {
            HostsList = new List<string>();
            hostsfilename = filename;
            string[] lines = System.IO.File.ReadAllLines(filename);
            foreach (string line in lines)
            {
                if (!line.StartsWith('#'))
                {
                    string[] host = line.Trim().Split(" ");
                    string hostname = "";
                    for (int i = 1; i < host.Length; i++)
                    {
                        if (!host[i].Trim().Equals(""))
                        {
                            hostname = host[i];
                            break;
                        }
                    }
                    if (!hostname.Equals(""))
                    {
                        if (!HostsList.Contains(hostname))
                        {
                            HostsList.Add(hostname);
                        }
                    }
                }
            }
        }
        public int AppendEntry(string[] urls)
        {
            int count = 0;
            Regex ipmatch = new Regex("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}");
            using StreamWriter file = new StreamWriter(hostsfilename, append: true);

            foreach (string url in urls)
            {
                string url2 = url.Trim();
                if ( url2.Equals(""))
                {
                    continue;
                }
                if (!(url2.StartsWith("https://") || url2.StartsWith("http://")))
                {
                    url2 = "https://" + url2;
                }
                try
                {
                    Uri uri = new Uri(url2);
                    if (HostsList.Contains(uri.Host))
                    {
                        continue;
                    }
                    if( ipmatch.IsMatch(uri.Host) )
                    {
                        continue;
                    }
                    string entry = "127.0.0.1 " + uri.Host;
                    file.WriteLine(entry);
                    HostsList.Add(uri.Host);
                    count++;
                }
                catch(UriFormatException) { }
            }
            file.Flush();
            return count;
        }
    }
    class NetshFirewall
    {
        public int BlockIP(string[] urls)
        {
            int count = 0;
            Regex ipmatch = new Regex("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}");
            
            foreach (string url in urls)
            {
                string url2 = url.Trim();
                if (url2.Equals(""))
                {
                    continue;
                }
                if (!(url2.StartsWith("https://") || url2.StartsWith("http://")))
                {
                    url2 = "https://" + url2;
                }
                try
                {
                    Uri uri = new Uri(url2);
                    if (!ipmatch.IsMatch(uri.Host))
                    {
                        continue;
                    }
                    string cmdparam = "advfirewall firewall show rule name=\"Block " + uri.Host + "\"";
                    Process proc = Process.Start(Environment.GetEnvironmentVariable("windir") + @"\system32\netsh.exe", cmdparam);
                    proc.WaitForExit();
                    if( proc.ExitCode == 0 )
                    {
                        continue;
                    }
                    cmdparam = "advfirewall firewall add rule name=\"Block " + uri.Host + "\" dir=out remoteip=" + uri.Host + " action=block";
                    proc = Process.Start(Environment.GetEnvironmentVariable("windir") + @"\system32\netsh.exe", cmdparam);
                    proc.WaitForExit();
                    count++;
                }
                catch (UriFormatException) { }
            }
             return count;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Configuration config = new Configuration();
                config.Read("config.xml");
                if (config.HostsFilename.Equals(""))
                    return;
                if (config.ImportFilename.Equals(""))
                    return;
                if (config.PublicKey.Equals(""))
                    return;
                string[] signature = File.ReadAllLines(config.ImportFilename + ".signature");
                if (signature.Length == 0 || signature.Length > 1)
                    return;
                RSA rsa = RSA.Create();
                rsa.ImportRSAPublicKey(Convert.FromBase64String(config.PublicKey), out int bytesread);
                if (!rsa.VerifyData(File.ReadAllBytes(config.ImportFilename), Convert.FromBase64String(signature[0]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    Console.WriteLine("Verification failed!");
                    return;
                }  
                string[] urls = System.IO.File.ReadAllLines(config.ImportFilename);
                if (urls.Length == 0)
                    return;
                HostFile hostFile = new HostFile();
                hostFile.Read(config.HostsFilename);
                int count = hostFile.AppendEntry(urls);
                Console.WriteLine(count + " records written");
                NetshFirewall firewall = new NetshFirewall();
                firewall.BlockIP(urls);
            }
            catch(System.IO.FileNotFoundException e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
