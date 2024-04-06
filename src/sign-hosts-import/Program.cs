using System;
using System.IO;
using System.Security.Cryptography;

namespace sign_hosts_import
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Configuration config = new Configuration();
                config.Read("config.xml");
                if (config.ImportFilename.Equals(""))
                    return;
                byte[] filecontents = File.ReadAllBytes(config.ImportFilename);
                Console.WriteLine("Enter password:");
                string password = Console.ReadLine();
                RSA rsa = RSA.Create();
                rsa.ImportEncryptedPkcs8PrivateKey(password, Convert.FromBase64String(config.PrivateKey), out int bytesread);
                byte[] signature = rsa.SignData(filecontents, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using StreamWriter file = new StreamWriter(config.ImportFilename+".signature");
                file.WriteLine(Convert.ToBase64String(signature));
                file.Flush();
            }
            catch (System.IO.FileNotFoundException e)
            {
                Console.WriteLine(e);
            }
            catch (System.Security.Cryptography.CryptographicException e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
