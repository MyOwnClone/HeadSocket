#include <iostream>

#define HEADSOCKET_IMPLEMENTATION
#include "headsocket.h"

int main()
{
  int port = 42666;
  headsocket::TcpServer server(port);

  if (server.isRunning())
    std::cout << "Server running at port " << port << std::endl;
  else
    std::cout << "Could not start server on port " << port << std::endl;
 
  getchar();
  return 0;
}
