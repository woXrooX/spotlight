#ifndef SPOTLIGHT_H
#define SPOTLIGHT_H

#include <iostream>
#include <netinet/in.h>       // socket & AF_PACKET & SOCK_RAW & IPPROTO_TCP
#include <unistd.h>           // read
#include <net/ethernet.h>     // ETH_P_ALL

// #include <linux/if_packet.h>
// #include <arpa/inet.h>
// #include <sys/socket.h>
// #include <netinet/tcp.h>
// #include <sys/types.h>

namespace woXrooX{
  class Spotlight final{
  public:
    static void observe(){
      std::cout << "\033[1;33m" << "Starting..." << "\033[0m\n";
      Spotlight::create_socket();

      while(true){
        Spotlight::in();

      }

    }

  private:
    static void create_socket(){
      // 0 indicates that the caller does not want to specify the protocol and will leave it up to the service provider.
      // IPPROTO_TCP
      // All Protocols -> htons(ETH_P_ALL)
      Spotlight::fd_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
      if(Spotlight::fd_socket < 0) std::cout << "\033[40;31m" << "Failed To Create Socket Descriptor." << "\033[0m\n";
      else std::cout << "\033[1;32m" << "Socket Descriptor Created Successfully." << "\033[0m\n";

    }

    static void in(){
      if(Spotlight::fd_socket == -1) return;

      unsigned char inData[Spotlight::BUFFER_SIZE];
      int received_data_size = 0;

      do{
        Spotlight::bytes_received = read(Spotlight::fd_socket, inData, Spotlight::BUFFER_SIZE);

        received_data_size += Spotlight::bytes_received;

        // if(received_data_size > Spotlight::BUFFER_SIZE-1 || inData[Spotlight::BUFFER_SIZE-1] == '\n') break;
        if(Spotlight::bytes_received == -1){std::cout << "\033[40;31m" << "Failed To Receive Data." << "\033[0m\n"; return;}
        if(Spotlight::bytes_received == 0){std::cout << "\033[40;33m" << "End Of The Line" << "\033[0m\n"; break;}
        if(Spotlight::bytes_received > 0){
          std::cout << "\033[40;94m" << "Data Received Successfully!" << "\033[0m\n";
          std::cout << inData << '\n';
          break;
        }

      }while(true);

    }

    // Variables
    static int fd_socket;
    static int bytes_received;
    static int BUFFER_SIZE;

  };
  int Spotlight::fd_socket = -1;
  int Spotlight::bytes_received = 0;
  // int Spotlight::BUFFER_SIZE = 512;
  int Spotlight::BUFFER_SIZE = 262144; // 512kb | 256kb
}
#endif
