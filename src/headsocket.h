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

#define HEADSOCKET_SWAP16(value) (((value) >> 8) | ((value) << 8))
#define HEADSOCKET_SWAP32(value) \
  ((((value) >> 24) & 0xFF) | \
  (((value) << 8) & 0xFF0000) | \
  (((value) >> 8) & 0xFF00) | \
  (((value) << 24) & 0xFF000000))

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Forward declarations */
namespace std { class thread; }

namespace headsocket {

/* Forward declarations */
struct ConnectionParams;
class SHA1;
class TcpServer;
class TcpClient;

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

struct Encoding
{
  static size_t base64(const void *src, size_t srcLength, void *dst, size_t dstLength);
  static size_t xor32(uint32_t key, void *ptr, size_t length);
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class TcpServer
{
public:
  TcpServer(int port);
  virtual ~TcpServer();

  void stop();
  bool isRunning() const;

protected:
  virtual TcpClient *clientAccept(ConnectionParams *params);
  virtual void clientConnected(TcpClient *client);
  virtual void clientDisconnected(TcpClient *client);

  struct TcpServerImpl *_p;

private:
  void listenThread();
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class TcpClient
{
public:
  TcpClient(const char *address, int port, bool makeAsync = false);
  TcpClient(TcpServer *server, ConnectionParams *params, bool makeAsync = false);
  virtual ~TcpClient();

  void disconnect();
  bool isConnected() const;
  bool isAsync() const;

  size_t write(const void *ptr, size_t length);
  bool forceWrite(const void *ptr, size_t length);
  size_t read(void *ptr, size_t length);
  size_t readLine(void *ptr, size_t length);
  bool forceRead(void *ptr, size_t length);

protected:
  void initAsyncThreads();
  virtual void asyncWriteHandler(const uint8_t *ptr, size_t length);
  virtual void asyncReadHandler(uint8_t *ptr, size_t length);

  struct TcpClientImpl *_p;

private:
  void writeThread();
  void readThread();
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
#include <map>

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
SHA1::SHA1(): _blockByteIndex(0), _byteCount(0)
{
  uint32_t *d = _digest;
  *d++ = 0x67452301; *d++ = 0xEFCDAB89; *d++ = 0x98BADCFE; *d++ = 0x10325476;*d++ = 0xC3D2E1F0;
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
  while (begin != end) processByte(*begin++);
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processBytes(const void *data, size_t len) { processBlock(data, static_cast<const uint8_t *>(data) + len); }

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
  for (int i = 24; i >= 0; i -= 8) processByte(static_cast<unsigned char>((bitCount >> i) & 0xFF));

  memcpy(digest, _digest, 5 * sizeof(uint32_t));
  return digest;
}

//---------------------------------------------------------------------------------------------------------------------
const uint8_t *SHA1::getDigestBytes(Digest8 digest)
{
  Digest32 d32; getDigest(d32);
  size_t s[] = { 24, 16, 8, 0 };

  for (size_t i = 0, j = 0; i < 20; ++i, j = i % 4) digest[i] = ((d32[i >> 2] >> s[j]) & 0xFF);
  
  return digest;
}

//---------------------------------------------------------------------------------------------------------------------
void SHA1::processBlock()
{
  uint32_t w[80], s[] = { 24, 16, 8, 0 };

  for (size_t i = 0, j = 0; i < 64; ++i, j = i % 4) w[i >> 2] = j ? (w[i >> 2] | (_block[i] << s[j])) : (_block[i] << s[j]);
  for (size_t i = 16; i < 80; i++) w[i] = rotateLeft((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
  Digest32 dig = { _digest[0], _digest[1], _digest[2], _digest[3], _digest[4] };

  for (size_t f, k, i = 0; i < 80; ++i)
  {
    if (i < 20) f = (dig[1] & dig[2]) | (~dig[1] & dig[3]), k = 0x5A827999;
    else if (i < 40) f = dig[1] ^ dig[2] ^ dig[3], k = 0x6ED9EBA1;
    else if (i < 60) f = (dig[1] & dig[2]) | (dig[1] & dig[3]) | (dig[2] & dig[3]), k = 0x8F1BBCDC;
    else f = dig[1] ^ dig[2] ^ dig[3], k = 0xCA62C1D6;

    uint32_t temp = rotateLeft(dig[0], 5) + f + dig[4] + k + w[i];
    dig[4] = dig[3]; dig[3] = dig[2];
    dig[2] = rotateLeft(dig[1], 30);
    dig[1] = dig[0]; dig[0] = temp;
  }

  for (size_t i = 0; i < 5; ++i) _digest[i] += dig[i];
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
size_t Encoding::base64(const void *src, size_t srcLength, void *dst, size_t dstLength)
{
  if (!src || !srcLength || !dst || !dstLength) return 0;

  static const char *encodingTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static size_t modTable[] = { 0, 2, 1 }, result = 4 * ((srcLength + 2) / 3);

  if (result <= dstLength - 1)
  {
    const uint8_t *input = reinterpret_cast<const uint8_t *>(src);
    uint8_t *output = reinterpret_cast<uint8_t *>(dst);

    for (size_t i = 0, j = 0, triplet = 0; i < srcLength; triplet = 0)
    {
      for (size_t k = 0; k < 3; ++k) triplet = (triplet << 8) | (i < srcLength ? (uint8_t)input[i++] : 0);
      for (size_t k = 4; k--; ) output[j++] = encodingTable[(triplet >> k * 6) & 0x3F];
    }

    for (size_t i = 0; i < modTable[srcLength % 3]; i++) output[result - 1 - i] = '=';
    output[result] = 0;
  }

  return result;
}

//---------------------------------------------------------------------------------------------------------------------
size_t Encoding::xor32(uint32_t key, void *ptr, size_t length)
{
  uint8_t *data = reinterpret_cast<uint8_t *>(ptr);
  uint8_t *mask = reinterpret_cast<uint8_t *>(&key);

  for (size_t i = 0; i < length; ++i, ++data) *data = (*data) ^ mask[i % 4];

  return length;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct TcpServerImpl
{
  std::atomic_bool isRunning;
  sockaddr_in local;
  LockableValue<std::vector<TcpClient *>> connections;
  int port = 0;
  SOCKET serverSocket = INVALID_SOCKET;
  std::thread *listenThread = nullptr;

  TcpServerImpl() { isRunning = false; }
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct ConnectionParams
{
  SOCKET clientSocket;
  sockaddr_in from;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
TcpServer::TcpServer(int port): _p(new TcpServerImpl())
{
#ifdef HEADSOCKET_PLATFORM_WINDOWS
  WSADATA wsaData;
  WSAStartup(0x101, &wsaData);
#endif

  _p->local.sin_family = AF_INET;
  _p->local.sin_addr.s_addr = INADDR_ANY;
  _p->local.sin_port = htons(static_cast<unsigned short>(port));

  _p->serverSocket = socket(AF_INET, SOCK_STREAM, 0);

  if (bind(_p->serverSocket, (sockaddr *)&_p->local, sizeof(_p->local)) != 0) return;
  if (listen(_p->serverSocket, 8)) return;

  _p->isRunning = true;
  _p->port = port;
  _p->listenThread = new std::thread(std::bind(&TcpServer::listenThread, this));
}

//---------------------------------------------------------------------------------------------------------------------
TcpServer::~TcpServer()
{
  stop();

#ifdef HEADSOCKET_PLATFORM_WINDOWS
  WSACleanup();
#endif

  delete _p;
}

//---------------------------------------------------------------------------------------------------------------------
TcpClient *TcpServer::clientAccept(ConnectionParams *params) { return new TcpClient(this, params); }

//---------------------------------------------------------------------------------------------------------------------
void TcpServer::clientConnected(TcpClient *client) { }

//---------------------------------------------------------------------------------------------------------------------
void TcpServer::clientDisconnected(TcpClient *client) { }

//---------------------------------------------------------------------------------------------------------------------
void TcpServer::stop()
{
  if (_p->isRunning.exchange(false))
  {
    closesocket(_p->serverSocket);

    if (_p->listenThread)
    {
      _p->listenThread->join();
      delete _p->listenThread; _p->listenThread = nullptr;
    }
  }
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

    if (!_p->isRunning) break;

    if (params.clientSocket != INVALID_SOCKET)
    {
      if (TcpClient *newClient = clientAccept(&params))
      {
        { HEADSOCKET_LOCK(_p->connections); _p->connections->push_back(newClient); }
        clientConnected(newClient);
      }
    }
  }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct TcpClientImpl
{
  std::atomic_bool isConnected;
  sockaddr_in from;
  CriticalSection writeCS;
  std::vector<uint8_t> writeBuffer;
  std::vector<std::tuple<size_t, size_t>> writeSegments;
  CriticalSection readCS;
  std::vector<uint8_t> readBuffer;
  std::vector<std::tuple<size_t, size_t>> readSegments;
  bool isAsync = false;
  TcpServer *server = nullptr;
  SOCKET clientSocket = INVALID_SOCKET;
  std::string address = "";
  int port = 0;
  std::thread *writeThread = nullptr;
  std::thread *readThread = nullptr;

  TcpClientImpl() { isConnected = false; }
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------------------------------------------------
TcpClient::TcpClient(const char *address, int port, bool makeAsync): _p(new TcpClientImpl())
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

  if (makeAsync) initAsyncThreads();
}

//---------------------------------------------------------------------------------------------------------------------
TcpClient::TcpClient(TcpServer *server, ConnectionParams *params, bool makeAsync): _p(new TcpClientImpl())
{
  _p->server = server;
  _p->clientSocket = params->clientSocket;
  _p->from = params->from;
  _p->isConnected = true;

  if (makeAsync) initAsyncThreads();
}

//---------------------------------------------------------------------------------------------------------------------
TcpClient::~TcpClient()
{
  disconnect();
  delete _p;
}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::disconnect()
{
  if (_p->isConnected.exchange(false))
  {
    if (!_p->server)
    {
      closesocket(_p->clientSocket);
      _p->clientSocket = INVALID_SOCKET;
    }

    if (_p->isAsync)
    {
      _p->isAsync = false;
      _p->writeThread->join(); _p->readThread->join();
      delete _p->writeThread; _p->writeThread = nullptr;
      delete _p->readThread; _p->readThread = nullptr;
    }
  }
}

//---------------------------------------------------------------------------------------------------------------------
bool TcpClient::isConnected() const { return _p->isConnected; }

//---------------------------------------------------------------------------------------------------------------------
bool TcpClient::isAsync() const { return _p->isAsync; }

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

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::initAsyncThreads()
{
  _p->isAsync = true;
  _p->writeBuffer.reserve(65536);
  _p->writeSegments.reserve(1024);
  _p->readBuffer.reserve(65536);
  _p->readSegments.reserve(1024);
  _p->writeThread = new std::thread(std::bind(&TcpClient::writeThread, this));
  _p->readThread = new std::thread(std::bind(&TcpClient::readThread, this));
}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::writeThread()
{
  while (_p->isConnected)
  {
  
  }

  std::cout << "Write thread closed" << std::endl;
}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::asyncWriteHandler(const uint8_t *ptr, size_t length)
{
  HEADSOCKET_LOCK(_p->writeCS);

}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::asyncReadHandler(uint8_t *ptr, size_t length)
{
  HEADSOCKET_LOCK(_p->readCS);

}

//---------------------------------------------------------------------------------------------------------------------
void TcpClient::readThread()
{
  uint8_t buff[1024];
  while (_p->isConnected)
  {
    int result = recv(_p->clientSocket, reinterpret_cast<char *>(buff), 1024, 0);
    if (!result || result == SOCKET_ERROR)
      break;

    std::cout << "Bytes received: " << result << std::endl;
    asyncReadHandler(buff, static_cast<size_t>(result));
  }

  std::cout << "Read thread closed" << std::endl;
}

}
#endif
#endif
