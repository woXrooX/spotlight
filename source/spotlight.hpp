#ifndef SPOTLIGHT_H
#define SPOTLIGHT_H

#include <iostream>
#include <netinet/in.h>       // socket & AF_PACKET & SOCK_RAW & IPPROTO_TCP
#include <unistd.h>           // read
#include <net/ethernet.h>     // ETH_P_ALL
// #include <netinet/ip.h>       // struct iphdr -> Unix-Like
#include <linux/ip.h>         // struct iphdr -> Linux

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
          std::cout << "\033[30;94m" << "Data Sniffed Successfully!" << "\033[0m\n";
          // std::cout << Spotlight::bytes_received << '\n';
          // std::cout << inData << '\n';
          Spotlight::processPacket(inData, received_data_size);
          break;
        }

      }while(true);

    }

    // void ProcessPacket(unsigned char* buffer, int size){
    static void processPacket(unsigned char* inData, int size){

      // https://stackoverflow.com/questions/42840636/difference-between-struct-ip-and-struct-iphdr
      // IP Header
      struct iphdr *iph = (struct iphdr*)inData;

      // Total Connections
      Spotlight::total++;

      // Individual Connections / Protocols
      switch(iph->protocol){
        case 1: // ICMP
          Spotlight::ICMP++;
          break;

        case 2: // IGMP
          Spotlight::IGMP++;
          break;

        case 6: // TCP
          Spotlight::TCP++;
          break;

        case 17: // UDP
          Spotlight::UDP++;
          break;

        default:
          Spotlight::unknown++;
          break;

      }

      std::cout
      << "ICMP: "       << Spotlight::ICMP
      << "\tIGMP: "     << Spotlight::IGMP
      << "\tTCP: "      << Spotlight::ICMP
      << "\tUDP: "      << Spotlight::ICMP
      << "\tTotal: "    << Spotlight::total
      << "\tUnknown: "  << Spotlight::unknown
      << '\n';

    }

    static void printIpHeader(){

    }

    ///////// Variables
    // Counts
    static int total, unknown;
    static int ICMP, IGMP, TCP, UDP;

    static int fd_socket;
    static int bytes_received;
    static int BUFFER_SIZE;

  };

  int Spotlight::total = 0;
  int Spotlight::unknown = 0;
  int Spotlight::ICMP = 0;
  int Spotlight::IGMP = 0;
  int Spotlight::TCP = 0;
  int Spotlight::UDP = 0;

  int Spotlight::fd_socket = -1;
  int Spotlight::bytes_received = 0;
  int Spotlight::BUFFER_SIZE = 512;
  // int Spotlight::BUFFER_SIZE = 262144; // 512kb | 256kb

}
#endif
