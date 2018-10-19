using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace TLS_Handshake_Proxy {
  public class Server {
    static void Main(string[] args) {
      Console.WriteLine("Hello World!");
    }
  }
  class TLSHandshakeServer {
    private TcpListener tcpListener;
    private byte[] key;
    bool isRunning = false;

    TLSHandshakeServer(int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.key = key;
    }

    async void start() {
      AsyncEchoServer().Wait();
    }

    void stop() { 
      isRunning = false;
    }
    
    async Task AsyncEchoServer() {
      tcpListener.Start();
      isRunning = true;
      while(isRunning) { 
        TcpClient tc = await tcpListener.AcceptTcpClientAsync().ConfigureAwait(false);
        Task.Factory.StartNew(AsyncTcpProcess, tc);
      }
    }
    async void AsyncTcpProcess(object o) {
      TcpClient tc = (TcpClient) o;
      NetworkStream stream = tc.GetStream();
      byte[] encryptedInput, decryptedOutput, encryptedOutput;
      string decryptedInput;
      int numBytesRead = 0;
      byte[] outBuf = new byte[1024];

      using(var ms = new MemoryStream()) {
        while ((numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) ms.Write(outBuf, 0, numBytesRead);
        encryptedInput = ms.ToArray();
      }
      decryptedInput = Encoding.UTF8.GetString(SecurityModule.AESDecrypt256(encryptedInput, key));
      string[] split = decryptedInput.Split('|');
      string ipAddr = split[0];
      int port = Int32.Parse(split[1]);
      byte[] data = Convert.FromBase64String(split[2]);

      TcpClient proxy = new TcpClient(ipAddr, port);
      NetworkStream proxyStream = proxy.GetStream();
      proxyStream.Write(data, 0, data.Length);

      using(var ms = new MemoryStream()) {
        while ((numBytesRead = proxyStream.Read(outBuf, 0, outBuf.Length)) > 0) ms.Write(outBuf, 0, numBytesRead);
        decryptedOutput = ms.ToArray();
      }

      encryptedOutput = SecurityModule.AESEncrypt256(decryptedOutput, key);
      stream.Write(encryptedOutput, 0, encryptedOutput.Length);
      stream.Flush();
      stream.Close();
    }
  }
}

