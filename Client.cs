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
  class TLSHandshakeClient {
    private TcpListener tcpListener;
    private String remoteIpAddr;
    private int remotePort;
    private byte[] key;
    bool isRunning = false;

    [DllImport("./liboriginaddr.so")]
    public static extern addr_type get_original_addr(int fd);
    public TLSHandshakeClient(int remotePort, String remoteIpAddr, int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.remotePort = remotePort;
      this.remoteIpAddr = remoteIpAddr;
      this.key = key;
    }
    public void start() {
      tcpListener.Start();
      isRunning = true;

      // while(isRunning) { 
        TcpClient tc = tcpListener.AcceptTcpClient();
        AsyncTcpProcess(tc);
        // Task.Factory.StartNew(AsyncTcpProcess, tc);
      // }
    }

    public void stop() { 
      isRunning = false;
      tcpListener.Stop();
    }

    void AsyncTcpProcess(object o) {
      TcpClient tc = (TcpClient) o;
      NetworkStream stream = tc.GetStream();
      System.Console.WriteLine("Socket connection established");
      byte[] ipClasses = new byte[4];
      byte[] outBuf = new byte[1024];
      int numBytesRead = 0;

      byte[] buff;
      int fd = (int) tc.Client.Handle;
      
      addr_type originalAddr = get_original_addr(fd);
      
      if(originalAddr.port == -1) {
        throw new Exception();
      }
      long ipLong = IPAddress.HostToNetworkOrder(originalAddr.ip & 0xFFFFFFFF) >> 32;
      foreach(int i in new int[]{ 0, 1, 2, 3 }) {
        ipClasses[i] = (byte)(ipLong >> (3-i)*8);
      }
      
      string ipAddr = String.Join('.', ipClasses);
      int nBytes = 0;
      using(var ms = new MemoryStream()) {
        while((numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) {
          ms.Write(outBuf, 0, outBuf.Length); 
          nBytes += numBytesRead;
          System.Console.WriteLine(numBytesRead);
          if(!stream.DataAvailable) break;
        }
        buff = new byte[nBytes];
        ms.Seek(0, SeekOrigin.Begin);
        ms.Read(buff, 0, nBytes);
      }
      System.Console.WriteLine(BitConverter.ToString(buff).Replace("-", " "));

      if(nBytes <= 0) return;
      
      if(buff[0] == 0x16) { // TLS Handshake packet
        System.Console.WriteLine("Handshake");
        byte[] encryptedData = SecurityModule.AESEncrypt256(buff, this.key);
        string bodyString = $"{ipAddr}|{originalAddr.port}|{Convert.ToBase64String(encryptedData)}";
        byte[] body = Encoding.UTF8.GetBytes(bodyString);
        byte[] encryptedInput, decryptedInput;
        System.Console.WriteLine($"Sending {bodyString}");

        TcpClient encrypted = new TcpClient(remoteIpAddr, remotePort);
        NetworkStream encryptedStream = encrypted.GetStream();
        encryptedStream.Write(body, 0, body.Length);

        using(var ms = new MemoryStream()) {
          while ((numBytesRead = encryptedStream.Read(outBuf, 0, outBuf.Length)) > 0) {
            ms.Write(outBuf, 0, numBytesRead);
            if(!encryptedStream.DataAvailable) break;
          }
          encryptedInput = ms.ToArray();
        }

        decryptedInput = SecurityModule.AESDecrypt256(encryptedInput, key);
        stream.Write(decryptedInput, 0, decryptedInput.Length);
      } else { // IDK just bypass it
        System.Console.WriteLine($"Normal Packet: Initiating connection to {ipAddr}:{originalAddr.port}");
        TcpClient bypass = new TcpClient(ipAddr, originalAddr.port);
        NetworkStream bypassStream = bypass.GetStream();

        System.Console.WriteLine($"Writing {nBytes} bytes to stream");
        bypassStream.Write(buff, 0, nBytes);
        
        while (bypassStream.DataAvailable && (numBytesRead = bypassStream.Read(outBuf, 0, outBuf.Length)) > 0) {
          stream.Write(outBuf, 0, numBytesRead);
          System.Console.WriteLine(bypassStream.DataAvailable);
          if(!bypassStream.DataAvailable) break;
        }
        System.Console.WriteLine("Normal Stream Closed");
      }
      stream.Flush();
      stream.Close();
      tc.Close();
    }
  }
}