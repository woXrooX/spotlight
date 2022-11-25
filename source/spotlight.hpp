#ifndef SPOTLIGHT_H
#define SPOTLIGHT_H

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h> // IPPROTO_TCP
// #include <netinet/tcp.h>
// #include <sys/types.h>

namespace woXrooX{
  class Spotlight final{
  public:
    static void observe(){
      std::cout << "\033[1;33mStarting...\033[0m" << '\n';
      Spotlight::create_socket();
      // Spotlight::in();

    }

  private:
    static void create_socket(){
      Spotlight::fd_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_TCP);
      if(Spotlight::fd_socket == -1) std::cout << "\033[1;31mFailed To Create Socket Descriptor.\033[0m" << '\n';
      else std::cout << "\033[0;32mSocket Descriptor Created Successfully.\033[0m" << '\n';

    }

    static void in(){
      if(Spotlight::fd_socket == -1) return;

      char inData[Spotlight::BUFFER_SIZE];
      int received_data_size = 0;

      do{
        Spotlight::bytes_received = recvfrom(Spotlight::fd_socket, inData, Spotlight::BUFFER_SIZE, 0, NULL, NULL);

        received_data_size += Spotlight::bytes_received;

        if(received_data_size > Spotlight::BUFFER_SIZE-1 || inData[Spotlight::BUFFER_SIZE-1] == '\n') break;
        if(Spotlight::bytes_received == -1){std::cout << "Failed To Receive Data." << '\n'; return;}
        if(Spotlight::bytes_received == 0){std::cout << "End Of The Line" << '\n'; break;}
        if(Spotlight::bytes_received > 0){
          std::cout <<  "Data Received Successfully" << '\n';
          std::cout << inData << '\n';
          // break;
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
