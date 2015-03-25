#include <iostream>

#define HEADSOCKET_IMPLEMENTATION
#include "headsocket.h"

namespace headsocket {

class WebSocketClient : public headsocket::TcpClient
{
public:
  typedef TcpClient Base;

  WebSocketClient(const char *address, int port);
  WebSocketClient(TcpServer *server, ConnectionParams *params);
  virtual ~WebSocketClient();

protected:
  void asyncWriteHandler(const uint8_t *ptr, size_t length) override;
  void asyncReadHandler(uint8_t *ptr, size_t length) override;

private:
  bool handshake();
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
WebSocketClient::WebSocketClient(const char *address, int port): Base(address, port, true)
{

}

//---------------------------------------------------------------------------------------------------------------------
WebSocketClient::WebSocketClient(TcpServer *server, ConnectionParams *params): Base(server, params, false)
{
  if (isConnected() && !handshake())
  {
    disconnect();
    return;
  }

  initAsyncThreads();
}

//---------------------------------------------------------------------------------------------------------------------
WebSocketClient::~WebSocketClient()
{

}

//---------------------------------------------------------------------------------------------------------------------
void WebSocketClient::asyncWriteHandler(const uint8_t *ptr, size_t length)
{
  HEADSOCKET_LOCK(_p->writeCS);

}

//---------------------------------------------------------------------------------------------------------------------
void WebSocketClient::asyncReadHandler(uint8_t *ptr, size_t length)
{
  HEADSOCKET_LOCK(_p->readCS);
  
}

//---------------------------------------------------------------------------------------------------------------------
bool WebSocketClient::handshake()
{
  std::string key;

  char lineBuffer[256];
  while (true)
  {
    size_t result = readLine(lineBuffer, 256);
    if (result <= 1)
      break;

    if (!memcmp(lineBuffer, "Sec-WebSocket-Key: ", 19))
      key = lineBuffer + 19;
  }

  if (key.empty())
    return false;

  key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  SHA1 sha;
  sha.processBytes(key.c_str(), key.length());

  SHA1::Digest8 digest;
  sha.getDigestBytes(digest);

  Encoding::base64(digest, 20, lineBuffer, 256);

  std::string response =
    "HTTP/1.1 101 Switching Protocols\n"
    "Upgrade: websocket\n"
    "Connection: Upgrade\n"
    "Sec-WebSocket-Accept: ";

  response += lineBuffer;
  response += "\n\n";

  write(response.c_str(), response.length());
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class WebSocketServer : public headsocket::TcpServer
{
public:
  typedef TcpServer Base;

  WebSocketServer(int port);
  virtual ~WebSocketServer();

  enum class FrameOpcode : uint8_t
  {
    Continuation = 0x00,
    Text = 0x01,
    Binary = 0x02,
    ConnectionClose = 0x08,
    Ping = 0x09,
    Pong = 0x0A,
  };

  struct FrameHeader
  {
    bool fin;
    FrameOpcode opcode;
    bool masked;
    uint64_t payloadLength;
    uint32_t maskingKey;
  };

  bool readFrameHeader(TcpClient *client, FrameHeader &header);

protected:
  TcpClient *clientAccept(ConnectionParams *params) override;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
WebSocketServer::WebSocketServer(int port)
  : Base(port)
{

}

//---------------------------------------------------------------------------------------------------------------------
WebSocketServer::~WebSocketServer()
{

}

//---------------------------------------------------------------------------------------------------------------------
TcpClient *WebSocketServer::clientAccept(ConnectionParams *params)
{
  TcpClient *newClient = new WebSocketClient(this, params);
  if (!newClient->isConnected())
  {
    delete newClient;
    newClient = nullptr;
  }
  else
  {
    FrameHeader header;
    if (readFrameHeader(newClient, header))
    {
      char buff[1024];
      newClient->read(buff, static_cast<size_t>(header.payloadLength));

      if (header.masked)
        Encoding::xor32(header.maskingKey, buff, static_cast<size_t>(header.payloadLength));

      if (header.opcode == FrameOpcode::Text)
      {
        buff[header.payloadLength] = 0;
        std::cout << buff << std::endl;
      }
    }
  }

  return newClient;
}

//---------------------------------------------------------------------------------------------------------------------
bool WebSocketServer::readFrameHeader(TcpClient *client, FrameHeader &header)
{
  uint8_t byte;

  if (!client->forceRead(&byte, 1)) return false;

  header.fin = (byte & 0x80) != 0;
  header.opcode = static_cast<FrameOpcode>(byte & 0x0F);

  if (!client->forceRead(&byte, 1)) return false;
  header.masked = (byte & 0x80) != 0;

  byte &= 0x7F;
  if (byte < 126) header.payloadLength = byte;
  else if (byte == 126)
  {
    uint16_t length;
    if (!client->forceRead(&length, 2)) return false;
    header.payloadLength = length;
  }
  else if (byte == 127)
    if (!client->forceRead(&header.payloadLength, 8)) return false;

  if (header.masked)
    if (!client->forceRead(&header.maskingKey, 4)) return false;

  return true;
}

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
  int port = 42666;
  headsocket::WebSocketServer server(port);

  if (server.isRunning())
    std::cout << "Server running at port " << port << std::endl;
  else
    std::cout << "Could not start server on port " << port << std::endl;
 
  getchar();
  return 0;
}
