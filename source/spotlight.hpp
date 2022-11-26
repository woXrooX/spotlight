#ifndef SPOTLIGHT_H
#define SPOTLIGHT_H

#include <iostream>
#include <iomanip>            // std::setfill
// #include <format>             // std::format
#include <unistd.h>           // read

#include <netinet/in.h>       // socket & AF_PACKET & SOCK_RAW & IPPROTO_TCP
#include <arpa/inet.h>        // inet_ntoa

#include <net/ethernet.h>     // ETH_P_ALL
#include <netinet/ip.h>       // struct iphdr -> Unix-Like
// #include <linux/ip.h>         // struct iphdr -> Linux

// #include <linux/if_packet.h>
// #include <sys/socket.h>
// #include <netinet/tcp.h>
// #include <sys/types.h>

namespace woXrooX{
  class Spotlight final{
  public:
    static void observe(){
      std::cout << "\033[1;33m" << "Starting..." << "\033[0m\n";
      Spotlight::create_socket();

      // Move The Loop Inside in
      while(true) Spotlight::in();

    }

  private:
    static void create_socket(){
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
          // std::cout << "\033[30;94m" << "Data Sniffed Successfully!" << "\033[0m\n";
          // std::cout << Spotlight::bytes_received << '\n';
          // std::cout << inData << '\n';
          Spotlight::processPacket(inData, received_data_size);
          break;
        }

      }while(true);

    }

    ////// Processes
    static void processPacket(unsigned char* inData, int size){
      // If you get 0x800 (ETH_P_IP), it means that the next header is the IP header. Later, we will consider the next header as the IP header

      // Ethernet Header
      struct ethhdr *eth = (struct ethhdr*)inData;

      // Total Connections
      Spotlight::total++;

      // Individual Connections / Protocols
      switch(eth->h_proto){
        case 8: // EGP
          Spotlight::EGP++;
          break;

        default:
          Spotlight::unknown++;
          break;

      }

      // Spotlight::processIPH(inData);
      Spotlight::outETH(eth->h_proto, eth->h_source, eth->h_dest);
      // Spotlight::outIPH();

    }

    static void processIPH(unsigned char* inData){
      // IP Header
      struct iphdr *iph = (struct iphdr*)(inData + sizeof(struct ethhdr));

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

        case 8: // EGP
          Spotlight::EGP++;
          break;

        case 17: // UDP
          Spotlight::UDP++;
          break;

        default:
          Spotlight::unknown++;
          break;

      }

      std::cout << "IP Version: " << (unsigned int)iph->version << '\n';

      std::cout << "Internet Header Length:" << '\n';
      std::cout << "DWORDS: " << (iph->ihl) << '\n';
      std::cout << "Bytes: " << ((iph->ihl)*4) << '\n';

      std::cout << "Type Of Service: " << (unsigned int)iph->tos << '\n';

      std::cout << "Total Length (Bytes): " << ntohs(iph->tot_len) << '\n';

      std::cout << "Identification: " << ntohs(iph->id) << '\n';

      std::cout << "Header Checksum: " << ntohs(iph->check) << '\n';

      // uint32 To Human Readable
      struct in_addr ip_source;
      ip_source.s_addr = iph->saddr;
      struct in_addr ip_destination;
      ip_destination.s_addr = iph->daddr;

      std::cout << "Source IP: " << inet_ntoa(ip_source) << '\n';
      std::cout << "Destination IP: " << inet_ntoa(ip_destination) << '\n';

    }

    ////// Outs
    static void outETH(int protocol, unsigned char source[6], unsigned char destination[6]){
      std::cout << "Ethernet Header" << '\n';

      // Source Address
      std::cout << "Source Address: ";
      for(std::size_t i = 0; i < 6; i++){
        std::cout
          << Spotlight::intToString(source[i])
          << ((i != 5) ? '-' : '\n');
      }

      // Destination Address
      std::cout << "Destination Address: ";
      for(std::size_t i = 0; i < 6; i++){
        std::cout
          << Spotlight::intToString(destination[i])
          << ((i != 5) ? '-' : '\n');
      }

      std::cout << "Protocol: " << protocol << '\n';

    }

    static void outIPH(){
      std::cout
      << "\x1b[2J"    // Clear Entire Terminal
      << "\x1b[1;1f"  // Move Cursor To 1:1
      << "ICMP: "       << Spotlight::ICMP
      << "\nIGMP: "     << Spotlight::IGMP
      << "\nTCP: "      << Spotlight::TCP
      << "\nEGP: "      << Spotlight::EGP
      << "\nUDP: "      << Spotlight::UDP
      << "\nTotal: "    << Spotlight::total
      << "\nUnknown: "  << Spotlight::unknown
      << '\n';

    }

    ////// Helpers
    static std::string intToString(unsigned char data){
      std::stringstream stream;
      stream
        << std::hex
        << std::setfill('0')
        << std::setw(2)
        << std::uppercase
        << (int)data;

        return stream.str();

    }

    ///////// Variables
    // Counters
    static int total, unknown;
    static int ICMP, IGMP, TCP, EGP, UDP;

    static int fd_socket;
    static int bytes_received;
    static int BUFFER_SIZE;

  };

  // Counters
  int Spotlight::total = 0;
  int Spotlight::unknown = 0;
  int Spotlight::ICMP = 0;
  int Spotlight::IGMP = 0;
  int Spotlight::TCP = 0;
  int Spotlight::EGP = 0;
  int Spotlight::UDP = 0;

  int Spotlight::fd_socket = -1;
  int Spotlight::bytes_received = 0;
  int Spotlight::BUFFER_SIZE = 262144; // 256kb

}

#endif
