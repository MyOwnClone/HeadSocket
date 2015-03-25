/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

* Minimalistic header only WebSocket server implementation in C++ *

/*/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma once

#include <stdint.h>

#ifndef HEADSOCKET_PLATFORM_OVERRIDE
#ifdef _WIN32
#define HEADSOCKET_PLATFORM_WINDOWS
#elif __ANDROID__
#define HEADSOCKET_PLATFORM_ANDROID
#elif __APPLE__
#include "TargetConditionals.h"
#ifdef TARGET_OS_MAC
#define HEADSOCKET_PLATFORM_MAC
#endif
#elif __linux
#define HEADSOCKET_PLATFORM_NIX
#elif __unix
#define HEADSOCKET_PLATFORM_NIX
#elif __posix
#define HEADSOCKET_PLATFORM_NIX
#else
#error Unsupported platform!
#endif
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Forward declarations */
namespace std { class thread; }

namespace headsocket {

/* Forward declarations */
class SHA1;
class TcpServer;
class TcpClient;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class WebSocketServer
{
public:
  WebSocketServer(int port);
  ~WebSocketServer();
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class SHA1
{
public:
  typedef uint32_t Digest32[5];
  typedef uint8_t Digest8[20];

  inline static uint32_t rotateLeft(uint32_t value, size_t count) { return (value << count) ^ (value >> (32 - count)); }

  SHA1();
  ~SHA1() { }

  void processByte(uint8_t octet);
  void processBlock(const void *start, const void *end);
  void processBytes(const void *data, size_t len);
  const uint32_t *getDigest(Digest32 digest);
  const uint8_t *getDigestBytes(Digest8 digest);

private:
  void processBlock();

  Digest32 _digest;
  uint8_t _block[64];
  size_t _blockByteIndex;
  size_t _byteCount;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct Base64
{
  static size_t encode(const void *src, size_t srcLength, void *dst, size_t dstLength);
  static size_t decode(const void *src, size_t srcLength, void *dst, size_t dstLength);
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class TcpServer
{
public:
  TcpServer(int port);
  ~TcpServer();

  struct Driver
  {
    virtual void onTcpClientConnected(TcpServer *sender, TcpClient *client) { }
    virtual void onTcpClientDisconnected(TcpServer *sender, TcpClient *client) { }
  };

  void assignDriver(Driver *driver);
  bool isRunning() const;

private:
  void listenThread();

  struct TcpServerImpl *_p;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class TcpClient
{
public:
  TcpClient(const char *address, int port);
  TcpClient(TcpServer *server, struct ConnectionParams *params);
  ~TcpClient();

  struct Driver
  {
  
  };

  void assignDriver(Driver *driver);
  bool isConnected() const;

  size_t write(const void *ptr, size_t length);
  bool forceWrite(const void *ptr, size_t length);
  size_t read(void *ptr, size_t length);
  size_t readLine(void *ptr, size_t length);
  bool forceRead(void *ptr, size_t length);

private:
  struct TcpClientImpl *_p;
};

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef HEADSOCKET_IMPLEMENTATION
#ifndef HEADSOCKET_IS_IMPLEMENTED
#define HEADSOCKET_IS_IMPLEMENTED

#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <mutex>

#ifdef HEADSOCKET_PLATFORM_WINDOWS
#pragma comment(lib, "ws2_32.lib")
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#endif

#define HEADSOCKET_LOCK_SUFFIX(var, suffix) std::lock_guard<decltype(var)> __scopeLock##suffix(var);
#define HEADSOCKET_LOCK_SUFFIX2(var, suffix) HEADSOCKET_LOCK_SUFFIX(var, suffix)
#define HEADSOCKET_LOCK(var) HEADSOCKET_LOCK_SUFFIX2(var, __LINE__)

namespace headsocket {

struct CriticalSection
{
  mutable std::atomic_bool consumerLock;

  CriticalSection() { consumerLock = false; }
  void lock() const { while (consumerLock.exchange(true)); }
  void unlock() const { consumerLock = false; }
};

template <typename T, typename M = CriticalSection>
struct LockableValue : M
{
  T value;
  T *operator->() { return &value; }
  const T *operator->() const { return &value; }
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
SHA1::SHA1()
  : _blockByteIndex(0)
  , _byteCount(0)
{
  _digest[0] = 0x67452301;
  _digest[1] = 0xEFCDAB89;
  _digest[2] = 0x98BADCFE;
  _digest[3] = 0x10325476;
  _digest[4] = 0xC3D2E1F0;
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processByte(uint8_t octet)
{
  _block[_blockByteIndex++] = octet;
  ++_byteCount;

  if (_blockByteIndex == 64)
  {
    _blockByteIndex = 0;
    processBlock();
  }
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processBlock(const void *start, const void *end)
{
  const uint8_t *begin = static_cast<const uint8_t *>(start);
  const uint8_t *finish = static_cast<const uint8_t *>(end);

  while (begin != finish)
  {
    processByte(*begin);
    begin++;
  }
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processBytes(const void *data, size_t len)
{
  const uint8_t *block = static_cast<const uint8_t *>(data);
  processBlock(block, block + len);
}

//---------------------------------------------------------------------------------------------------------------------
const uint32_t *SHA1::getDigest(Digest32 digest)
{
  size_t bitCount = _byteCount * 8;
  processByte(0x80);
  if (_blockByteIndex > 56)
  {
    while (_blockByteIndex != 0) processByte(0);
    while (_blockByteIndex < 56) processByte(0);
  }
  else
    while (_blockByteIndex < 56) processByte(0);

  processByte(0); processByte(0); processByte(0); processByte(0);
  processByte(static_cast<unsigned char>((bitCount >> 24) & 0xFF));
  processByte(static_cast<unsigned char>((bitCount >> 16) & 0xFF));
  processByte(static_cast<unsigned char>((bitCount >> 8) & 0xFF));
  processByte(static_cast<unsigned char>((bitCount)& 0xFF));

  memcpy(digest, _digest, 5 * sizeof(uint32_t));
  return digest;
}

//---------------------------------------------------------------------------------------------------------------------
const uint8_t *SHA1::getDigestBytes(Digest8 digest)
{
  Digest32 d32;
  getDigest(d32);
  size_t di = 0;

  digest[di++] = ((d32[0] >> 24) & 0xFF);
  digest[di++] = ((d32[0] >> 16) & 0xFF);
  digest[di++] = ((d32[0] >> 8) & 0xFF);
  digest[di++] = ((d32[0]) & 0xFF);

  digest[di++] = ((d32[1] >> 24) & 0xFF);
  digest[di++] = ((d32[1] >> 16) & 0xFF);
  digest[di++] = ((d32[1] >> 8) & 0xFF);
  digest[di++] = ((d32[1]) & 0xFF);

  digest[di++] = ((d32[2] >> 24) & 0xFF);
  digest[di++] = ((d32[2] >> 16) & 0xFF);
  digest[di++] = ((d32[2] >> 8) & 0xFF);
  digest[di++] = ((d32[2]) & 0xFF);

  digest[di++] = ((d32[3] >> 24) & 0xFF);
  digest[di++] = ((d32[3] >> 16) & 0xFF);
  digest[di++] = ((d32[3] >> 8) & 0xFF);
  digest[di++] = ((d32[3]) & 0xFF);

  digest[di++] = ((d32[4] >> 24) & 0xFF);
  digest[di++] = ((d32[4] >> 16) & 0xFF);
  digest[di++] = ((d32[4] >> 8) & 0xFF);
  digest[di++] = ((d32[4]) & 0xFF);

  return digest;
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processBlock()
{
  uint32_t w[80];

  for (size_t i = 0; i < 16; ++i)
  {
    w[i] = (_block[i * 4 + 0] << 24);
    w[i] |= (_block[i * 4 + 1] << 16);
    w[i] |= (_block[i * 4 + 2] << 8);
    w[i] |= (_block[i * 4 + 3]);
  }

  for (size_t i = 16; i < 80; i++)
    w[i] = rotateLeft((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);

  uint32_t a = _digest[0];
  uint32_t b = _digest[1];
  uint32_t c = _digest[2];
  uint32_t d = _digest[3];
  uint32_t e = _digest[4];

  for (size_t i = 0; i < 80; ++i)
  {
    uint32_t f = 0;
    uint32_t k = 0;

    if (i < 20)
    {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    }
    else if (i < 40)
    {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    }
    else if (i < 60)
    {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    }
    else
    {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }

    uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rotateLeft(b, 30);
    b = a;
    a = temp;
  }

  _digest[0] += a;
  _digest[1] += b;
  _digest[2] += c;
  _digest[3] += d;
  _digest[4] += e;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

size_t Base64::encode(const void *src, size_t srcLength, void *dst, size_t dstLength)
{
  if (!src || !srcLength || !dst || !dstLength)
    return 0;

  static const char *encodingTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static size_t modTable[] = { 0, 2, 1 };

  size_t result = 4 * ((srcLength + 2) / 3);

  if (result <= dstLength - 1)
  {
    const uint8_t *input = reinterpret_cast<const uint8_t *>(src);
    uint8_t *output = reinterpret_cast<uint8_t *>(dst);

    for (size_t i = 0, j = 0; i < srcLength; )
    {
      uint32_t octet_a = i < srcLength ? (uint8_t)input[i++] : 0;
      uint32_t octet_b = i < srcLength ? (uint8_t)input[i++] : 0;
      uint32_t octet_c = i < srcLength ? (uint8_t)input[i++] : 0;

      uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

      output[j++] = encodingTable[(triple >> 3 * 6) & 0x3F];
      output[j++] = encodingTable[(triple >> 2 * 6) & 0x3F];
      output[j++] = encodingTable[(triple >> 1 * 6) & 0x3F];
      output[j++] = encodingTable[(triple >> 0 * 6) & 0x3F];
    }

    for (size_t i = 0; i < modTable[srcLength % 3]; i++)
      output[result - 1 - i] = '=';

    output[result] = 0;
  }

  return result;
}

size_t Base64::decode(const void *src, size_t srcLength, void *dst, size_t dstLength)
{
  return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct TcpServerImpl
{
  std::atomic_bool isRunning;
  int port;
  sockaddr_in local;
  SOCKET serverSocket;
  std::thread *listenThread;

  LockableValue<std::vector<TcpClient *>> connections;
  LockableValue<TcpServer::Driver *> driver;

  TcpServerImpl()
    : port(0)
    , serverSocket(INVALID_SOCKET)
    , listenThread(nullptr)
  {
    isRunning = false;
    driver.value = nullptr;
  }
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct ConnectionParams
{
  SOCKET clientSocket;
  sockaddr_in from;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
TcpServer::TcpServer(int port)
  : _p(new TcpServerImpl())
{
#ifdef HEADSOCKET_PLATFORM_WINDOWS
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);

  _p->local.sin_family = AF_INET;
  _p->local.sin_addr.s_addr = INADDR_ANY;
  _p->local.sin_port = htons(static_cast<unsigned short>(port));

  _p->serverSocket = socket(AF_INET, SOCK_STREAM, 0);
#endif

  if (bind(_p->serverSocket, (sockaddr *)&_p->local, sizeof(_p->local)) != 0)
    return;

  if (listen(_p->serverSocket, 8))
    return;

  _p->isRunning = true;
  _p->port = port;
  _p->listenThread = new std::thread(std::bind(&TcpServer::listenThread, this));
}

//---------------------------------------------------------------------------------------------------------------------
TcpServer::~TcpServer()
{
  _p->isRunning = false;
  closesocket(_p->serverSocket);

  if (_p->listenThread)
  {
    _p->listenThread->join();
    delete _p->listenThread;
  }

#ifdef HEADSOCKET_PLATFORM_WINDOWS
  WSACleanup();
#endif

  delete _p;
}

//---------------------------------------------------------------------------------------------------------------------
void TcpServer::assignDriver(Driver *driver)
{
  HEADSOCKET_LOCK(_p->driver);
  _p->driver.value = driver;
}

//---------------------------------------------------------------------------------------------------------------------
bool TcpServer::isRunning() const { return _p->isRunning; }

//---------------------------------------------------------------------------------------------------------------------
void TcpServer::listenThread()
{
  while (_p->isRunning)
  {
    ConnectionParams params;
    params.clientSocket = accept(_p->serverSocket, (struct sockaddr *)&params.from, NULL);

    if (!_p->isRunning)
      break;

    if (params.clientSocket != INVALID_SOCKET)
    {
      HEADSOCKET_LOCK(_p->connections);
      TcpClient *newC = new TcpClient(this, &params);
      _p->connections->push_back(newC);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct TcpClientImpl
{
  std::atomic_bool isConnected;
  TcpServer *server;
  SOCKET clientSocket;
  sockaddr_in from;
  
  std::string address;
  int port;

  LockableValue<TcpClient::Driver *> driver;

  TcpClientImpl()
    : server(nullptr)
    , clientSocket(INVALID_SOCKET)
    , address("")
    , port(0)
  {
    isConnected = false;
    driver.value = nullptr;
  }
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
TcpClient::TcpClient(const char *address, int port)
  : _p(new TcpClientImpl())
{
  struct addrinfo *result = NULL, *ptr = NULL, hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char buff[16];
  sprintf_s(buff, "%d", port);

  if (getaddrinfo(address, buff, &hints, &result))
    return;

  for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
  {
    _p->clientSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (_p->clientSocket == INVALID_SOCKET)
      return;

    if (connect(_p->clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR)
    {
      closesocket(_p->clientSocket);
      _p->clientSocket = INVALID_SOCKET;
      continue;
    }

    break;
  }

  freeaddrinfo(result);

  if (_p->clientSocket == INVALID_SOCKET)
    return;

  _p->address = address;
  _p->port = port;
  _p->isConnected = true;
}

//---------------------------------------------------------------------------------------------------------------------
TcpClient::TcpClient(TcpServer *server, ConnectionParams *params)
  : _p(new TcpClientImpl())
{
  _p->server = server;
  _p->clientSocket = params->clientSocket;
  _p->from = params->from;

  _p->isConnected = true;

  std::string key;

  char lineBuffer[1024];
  while (true)
  {
    size_t result = readLine(lineBuffer, 1024);
    if (result <= 1)
      break;

    std::cout << lineBuffer << std::endl;
    
    if (!memcmp(lineBuffer, "Sec-WebSocket-Key: ", 19))
      key = lineBuffer + 19;
  }

  std::cout << "--- END OF HEADER ---" << std::endl;
  std::cout << key << std::endl;

  key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  SHA1 sha;
  sha.processBytes(key.c_str(), key.length());

  SHA1::Digest8 digest;
  sha.getDigestBytes(digest);

  Base64::encode(digest, 20, lineBuffer, 1024);
  std::cout << lineBuffer << std::endl;

  std::string response =
    "HTTP/1.1 101 Switching Protocols\n"
    "Upgrade: websocket\n"
    "Connection: Upgrade\n"
    "Sec-WebSocket-Accept: ";

  response += lineBuffer;
  response += "\n\n";

  write(response.c_str(), response.length());
}

//---------------------------------------------------------------------------------------------------------------------
TcpClient::~TcpClient()
{
  _p->isConnected = false;

  if (!_p->server)
    closesocket(_p->clientSocket);

  delete _p;
}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::assignDriver(Driver *driver)
{
  HEADSOCKET_LOCK(_p->driver);
  _p->driver.value = driver;
}

//---------------------------------------------------------------------------------------------------------------------
bool TcpClient::isConnected() const { return _p->isConnected; }

//---------------------------------------------------------------------------------------------------------------------
size_t TcpClient::write(const void *ptr, size_t length)
{
  if (!ptr || !length) return 0;
  int result = send(_p->clientSocket, (const char *)ptr, length, 0);
  if (result == SOCKET_ERROR)
    return 0;

  return static_cast<size_t>(result);
}

//---------------------------------------------------------------------------------------------------------------------
bool TcpClient::forceWrite(const void *ptr, size_t length)
{
  if (!ptr) return true;

  const char *chPtr = (const char *)ptr;

  while (length)
  {
    int result = send(_p->clientSocket, chPtr, length, 0);
    if (result == SOCKET_ERROR)
      return false;

    length -= (size_t)result;
    chPtr += result;
  }

  return true;
}

//---------------------------------------------------------------------------------------------------------------------
size_t TcpClient::read(void *ptr, size_t length)
{
  if (!ptr || !length) return 0;
  int result = recv(_p->clientSocket, (char *)ptr, length, 0);
  if (result == SOCKET_ERROR)
    return 0;

  return static_cast<size_t>(result);
}

//---------------------------------------------------------------------------------------------------------------------
size_t TcpClient::readLine(void *ptr, size_t length)
{
  if (!ptr || !length) return 0;

  size_t result = 0;
  while (result < length - 1)
  {
    char ch;
    int r = recv(_p->clientSocket, &ch, 1, 0);
    
    if (r == SOCKET_ERROR)
      return 0;
    
    if (r == 0 || ch == '\n')
      break;

    if (ch != '\r')
      reinterpret_cast<char *>(ptr)[result++] = ch;
  }

  reinterpret_cast<char *>(ptr)[result++] = 0;
  return result;
}

//---------------------------------------------------------------------------------------------------------------------
bool TcpClient::forceRead(void *ptr, size_t length)
{
  if (!ptr) return true;

  char *chPtr = (char *)ptr;

  while (length)
  {
    int result = recv(_p->clientSocket, chPtr, length, 0);
    if (result == SOCKET_ERROR)
      return false;

    length -= (size_t)result;
    chPtr += result;
  }

  return true;
}

}
#endif
#endif
