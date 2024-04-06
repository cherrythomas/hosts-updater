using System;
using System.Xml;

public class Configuration
{
    public string PrivateKey { get; set; }
    public string PublicKey { get; set; }
    public string HostsFilename { get; set; }
    public string ImportFilename { get; set; }

    public Configuration()
    {
    }
    public void Read(String filename)
    {
        using (XmlReader reader = XmlReader.Create(filename))
        {
            while (reader.Read())
            {
                if (reader.IsStartElement())
                {
                    //return only when you have START tag  
                    switch (reader.Name.ToString())
                    {
                        case "PrivateKey":
                            PrivateKey = reader.ReadString();
                            break;
                        case "PublicKey":
                            PublicKey = reader.ReadString();
                            break;
                        case "ImportFilename":
                            ImportFilename = reader.ReadString();
                            break;
                        case "HostsFilename":
                            HostsFilename = reader.ReadString();
                            break;
                    }
                }
            }
        }

    }
    public void Write(string filename)
    {
        using (XmlWriter writer = XmlWriter.Create(filename))
        {
            writer.WriteStartElement("Configuration");
            writer.WriteElementString("HostsFilename", HostsFilename);
            writer.WriteElementString("ImportFilename", ImportFilename);
            writer.WriteElementString("PrivateKey", PrivateKey);
            writer.WriteElementString("PublicKey", PublicKey);
            writer.Flush();
        }

    }
}

