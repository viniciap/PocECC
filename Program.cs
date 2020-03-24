using System;
using System.Security.Cryptography;

namespace PocECC
{
    public class Program
    {

        public static void Main(string[] args)
        {
            //App Eco
            var chaves = API.GerarChaves();

            Desktop.ImportarChaves(chaves);

            EnviarMsgDesktopAPI();
            EnviarMsgAPIDesktop();

            Console.ReadLine();
        }

        static void EnviarMsgDesktopAPI()
        {
            var msg = Desktop.EnviarMensagem("Teste Client -> Server");
            Console.WriteLine(API.ReceberMensagem(msg));
        }

        static void EnviarMsgAPIDesktop()
        {
            var msg = API.EnviarMensagem("Teste Server -> Client");
            Console.WriteLine(Desktop.ReceberMensagem(msg));
        }

        public class API
        {
            //public static byte[] ChaveClientServer { get; set; }
            public static byte[] ChaveServerClient { get; set; }

            public static Tuple<byte[], byte[]> GerarChaves()
            {
                var dna = new Dna();

                var serverKeys = dna.GenerateKeys();
                var clientKeys = dna.GenerateKeys();

                var ServerPrivateKey = serverKeys.Export(CngKeyBlobFormat.EccPrivateBlob);
                var ClientPrivateKey = clientKeys.Export(CngKeyBlobFormat.EccPrivateBlob);

                var ServerPublicKey = serverKeys.Export(CngKeyBlobFormat.EccPublicBlob);
                var ClientPublicKey = clientKeys.Export(CngKeyBlobFormat.EccPublicBlob);

                var derivedKeyServerClient = dna.DeriveKeyMaterial(ServerPrivateKey, ClientPublicKey);
                var derivedKeyClientServer = dna.DeriveKeyMaterial(ClientPrivateKey, ServerPublicKey);

                //ChaveClientServer = derivedKeyClientServer;
                ChaveServerClient = derivedKeyServerClient;

                return new Tuple<byte[], byte[]>(derivedKeyServerClient, derivedKeyClientServer);
            }


            public static Tuple<byte[], byte[]> EnviarMensagem(string message)
            {
                var dna = new Dna();

                return dna.EncryptMessage(ChaveServerClient, message);
            }

            public static string ReceberMensagem(Tuple<byte[], byte[]> message)
            {
                var dna = new Dna();

                return dna.DecryptMessage(ChaveServerClient, message.Item1, message.Item2);
            }



        }

        public class Desktop
        {
            public static byte[] ChaveClientServer { get; set; }
            //public static byte[] ChaveServerClient { get; set; }

            public static void ImportarChaves(Tuple<byte[], byte[]> chaves)
            {
                //ChaveServerClient = chaves.Item1;
                ChaveClientServer = chaves.Item2;
            }

            public static Tuple<byte[], byte[]> EnviarMensagem(string message)
            {
                var dna = new Dna();

                return dna.EncryptMessage(ChaveClientServer, message);
            }

            public static string ReceberMensagem(Tuple<byte[], byte[]> message)
            {
                var dna = new Dna();

                return dna.DecryptMessage(ChaveClientServer, message.Item1, message.Item2);
            }

        }

    }
}