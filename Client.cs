using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TLS_Handshake_Proxy {
  struct addr_type {
    public long ip;
    public int port;
  }
  public class Client {
    static void main(string[] args) {

    }
  }

  class TLSHandshakeClient {
    private TcpListener tcpListener;
    private String remoteIpAddr;
    private int remotePort;
    private byte[] key;
    bool isRunning = false;

    [DllImport("liboriginaddr.so")]
    public static extern addr_type get_original_addr(int fd);
    TLSHandshakeClient(int remotePort, String remoteIpAddr, int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.remotePort = remotePort;
      this.remoteIpAddr = remoteIpAddr;
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
      int MAX_SIZE = 16 * 1024 + 5;
      byte[] outBuf = new byte[1024];
      int numBytesRead = 0;

      byte[] buff = new byte[MAX_SIZE];
      int fd = (int) tc.Client.Handle;
      
      addr_type originalAddr = get_original_addr(fd);
      
      if(originalAddr.port == -1) {
        throw new Exception();
      }

      string ipAddr = new IPAddress(originalAddr.ip).ToString();
      int nBytes = await stream.ReadAsync(buff, 0, buff.Length).ConfigureAwait(false);

      if(nBytes <= 0) return;
      
      if((buff[0] ^ 0x16) == 1) { // TLS Handshake packet
        byte[] encryptedData = SecurityModule.AESEncrypt256(buff, this.key);
        string bodyString = $"{ipAddr}|{originalAddr.port}|{Convert.ToBase64String(encryptedData)}";
        byte[] body = Encoding.UTF8.GetBytes(bodyString);
        byte[] encryptedInput, decryptedInput;

        TcpClient encrypted = new TcpClient(remoteIpAddr, remotePort);
        NetworkStream encryptedStream = encrypted.GetStream();

        using(var ms = new MemoryStream()) {
          while ((numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) ms.Write(outBuf, 0, numBytesRead);
          encryptedInput = ms.ToArray();
        }

        decryptedInput = SecurityModule.AESDecrypt256(encryptedInput, key);
        stream.Write(decryptedInput, 0, decryptedInput.Length);
        stream.Flush();
        stream.Close();
      } else { // IDK just bypass it
        
        TcpClient bypass = new TcpClient(ipAddr, originalAddr.port);
        NetworkStream bypassStream = bypass.GetStream();

        bypassStream.Write(buff, 0, buff.Length);
        
        while ((numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) stream.Write(outBuf, 0, numBytesRead);
        stream.Flush();
        stream.Close();
      }
    }
  }
}