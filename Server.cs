﻿using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TLS_Handshake_Proxy {
  public class TLSHandshakeServer {
    private TcpListener tcpListener;
    private byte[] key;
    bool isRunning = false;

    public TLSHandshakeServer(int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.key = key;
    }

    public async void start() {
      AsyncEchoServer().Wait();
    }

    public void stop() { 
      isRunning = false;
      tcpListener.Stop();
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
      byte[] data;
      int numBytesRead = 0;
      byte[] outBuf = new byte[1024];

      using(var ms = new MemoryStream()) {
        while (stream.DataAvailable && (numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) {
          ms.Write(outBuf, 0, numBytesRead);
          if(!stream.DataAvailable) break;
        }
        encryptedInput = ms.ToArray();
      }
      string[] split = Encoding.UTF8.GetString(encryptedInput).Split('|');
      string ipAddr = split[0];
      int port = Int32.Parse(split[1]);
      data = SecurityModule.AESDecrypt256(Convert.FromBase64String(split[2]), key);

      System.Console.WriteLine(BitConverter.ToString(data).Replace('-', ' '));
      System.Console.WriteLine($"Opening socket to {ipAddr}:{port}");
      TcpClient proxy = new TcpClient(ipAddr, port);
      proxy.NoDelay = true;
      System.Console.WriteLine($"Socket opened to {ipAddr}:{port} - sending {data.Length} bytes");
      NetworkStream proxyStream = proxy.GetStream();
      proxyStream.Write(data, 0, data.Length);
      proxyStream.Flush();
      System.Console.WriteLine($"Sent {data.Length} bytes");

      int nBytes = 0;
      using(var ms = new MemoryStream()) {
        while ((numBytesRead = proxyStream.Read(outBuf, 0, outBuf.Length)) > 0) {
          ms.Write(outBuf, 0, numBytesRead);
          nBytes += numBytesRead;
          if(!proxyStream.DataAvailable) break;
        }
        decryptedOutput = ms.ToArray();
      }
      System.Console.WriteLine($"Received {nBytes} bytes");

      encryptedOutput = SecurityModule.AESEncrypt256(decryptedOutput, key);
      stream.Write(encryptedOutput, 0, nBytes);
      stream.Flush();
      stream.Close();
    }
  }
}

