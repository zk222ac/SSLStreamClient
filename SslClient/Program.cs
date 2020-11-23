using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SslClient
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //Client certificate
                string clientCertificateFile = "C:/Certificates/RootCA.pfx";
                // x509 certificate ( Load X509 certificate from File)
                X509Certificate cer = new X509Certificate(clientCertificateFile, "secret");
                // define TLS (transport layer security) protocol
                SslProtocols enabledSSLProtocols = SslProtocols.Tls;
                //Alternative for validation of client
                // or collection of X509 certificates
                X509CertificateCollection certificateCollection = new X509CertificateCollection { cer };
                // Server certificate name "FakeServerName" mentioned inside the ServerSSL certificate
                // ServerSSL cer issue to "FakeServerName"
                string targetHostName = "FakeServerName";
                TcpClient clientSocket = new TcpClient("localhost", 6789);
                Stream unsecuredStream = clientSocket.GetStream();
                //No revocation
                // SslStream sslStream = new SslStream(unsecuredStream, leaveInnerStreamOpen, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                //Setup for handling the validation of server
                // Verify the remote secure socket layer (SSL) certificate used for authentication
                // https://docs.microsoft.com/en-us/dotnet/api/system.net.security.remotecertificatevalidationcallback?view=net-5.0
                var remoteCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                // select the local secure socket layer (SSL) certificate used for authentication
                var localCertificateSelectionCallback = new LocalCertificateSelectionCallback(CertificateSelectionCallback);
                
                // ........................................SSL Stream CLass ...................................................................................

                SslStream sslStream = new SslStream(unsecuredStream, false, remoteCertificateValidationCallback, null);
                sslStream.AuthenticateAsClient(targetHostName, certificateCollection, enabledSSLProtocols, false);
                // https://searchsecurity.techtarget.com/definition/Certificate-Revocation-List ( why we choose true option in a different machine)
                // sslStream.AuthenticateAsClient(serverName, certificateCollection, enabledSSLProtocols, true); // client and server runs on different machine

                // ...................................................................................................
                StreamReader sr = new StreamReader(sslStream);
                StreamWriter sw = new StreamWriter(sslStream) { AutoFlush = true };
                // enable automatic flushing
                Console.WriteLine("Client authenticated");
                for (int i = 0; i < 5; i++)
                {
                    Console.WriteLine("Enter your message here:");
                    string message = Console.ReadLine();
                    sw.WriteLine(message);
                    string serverAnswer = sr.ReadLine();
                    Console.WriteLine("Server: " + serverAnswer);
                }
                sslStream.Close();
                clientSocket.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine("Press Enter to finish the Client ");
                Console.ReadKey();
            }
        }
        // Delegate Method call for certificate validation 
        private static bool ValidateServerCertificate(object sender, X509Certificate serverCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Client Sender: " + sender);
            Console.WriteLine("Client server certificate : " + serverCertificate);
            Console.WriteLine("Client Policy errors: " + sslPolicyErrors);
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Client validation of server certificate successful.");
                return true;
            }
            Console.WriteLine("Errors in certificate validation:");
            Console.WriteLine(sslPolicyErrors);
            return false;
        }
        private static X509Certificate CertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCollection, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            return localCollection[0];
        }
    }
    
}
