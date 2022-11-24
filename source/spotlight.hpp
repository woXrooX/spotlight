#ifndef SPOTLIGHT_H
#define SPOTLIGHT_H

#include <iostream>
#include <sys/socket.h>

namespace woXrooX{
  class Spotlight final{
  public:
    static void observe(){
      std::cout << "Starting..." << '\n';
      Spotlight::create_raw_socket();
      Spotlight::in();

    }

  private:
    static void create_raw_socket(){
      Spotlight::raw_socket_fd = socket(PF_PACKET, SOCK_RAW, 6);
      // Spotlight::raw_socket_fd = socket(AF_INET, SOCK_RAW, 6);
      if(Spotlight::raw_socket_fd == -1) std::cout << "Failed To Create Socket Descriptor." << '\n';
      else std::cout << "Socket Descriptor Created Successfully." << '\n';

    }

    static void in(){
      if(Spotlight::raw_socket_fd == -1) return;

      char inData[Spotlight::BUFFER];
      int received_data_size = 0;

      do{
        Spotlight::bytes_received = recvfrom(Spotlight::raw_socket_fd, inData, Spotlight::BUFFER, 0, NULL, NULL);

        received_data_size += Spotlight::bytes_received;

        if(received_data_size > Spotlight::BUFFER-1 || inData[Spotlight::BUFFER-1] == '\n') break;
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
    static int raw_socket_fd;
    static int bytes_received;
    static int BUFFER;

  };
  int Spotlight::raw_socket_fd = -1;
  int Spotlight::bytes_received = 0;
  // int Spotlight::BUFFER = 512;
  int Spotlight::BUFFER = 262144; // 512kb | 256kb
}
#endif
