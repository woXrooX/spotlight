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
#include <netinet/tcp.h>      // struct tcphdr
// #include <linux/ip.h>         // struct iphdr -> Linux

// #include <linux/if_packet.h>
// #include <sys/socket.h>
// #include <sys/types.h>

namespace woXrooX{
  class Spotlight final{
  public:
    static void observe(){
      Spotlight::brand();

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
      std::cout << "\n---------------------- processPacket ----------------------" << '\n';

      // If you get 0x800 (ETH_P_IP), it means that the next header is the IP header. Later, we will consider the next header as the IP header

      //// Ethernet Header
      // In the raw data, the Ethernet header comes before the IP header. The Ethernet header is typically 14 bytes long, and the IP header follows it.
      struct ethhdr *eth = (struct ethhdr*)inData;
      // Destination MAC Address h_dest
      // Source MAC Address h_source
      // Protocol Type h_proto

      //// VLAN Tag
      // struct vlan_tag *vlan = (struct vlan_tag*)(inData + sizeof(struct ethhdr));
      // if(eth->h_proto == htons(ETH_P_8021Q)){
      //   std::cout << "VLAN ID: " << ntohs(vlan->vlan_id) << std::endl;
      // }

      struct iphdr *iph = (struct iphdr*)(inData + sizeof(struct ethhdr));

      // Total Connections
      Spotlight::total++;

      std::cout << "Ethernet Header Protocol In HEX: 0x" << std::setfill('0') << std::setw(4) << std::hex << ntohs(eth->h_proto) << '\n';
      std::cout << "Ethernet Header Protocol In DEC: " << eth->h_proto << '\n';

      // Individual Connections / Protocols
      switch(ntohs(eth->h_proto)){
      // switch(eth->h_proto){
        case 0x08: // EGP
          std::cout << "EGP" << '\n';
          Spotlight::EGP++;
          // Spotlight::outETH(eth->h_proto, eth->h_source, eth->h_dest);
          break;


        case 0x0800: // Next Is IP Header | IPv4
          std::cout << "IP Header" << '\n';
          // Spotlight::outIPH(iph);
          break;

        case 0x0804: // HDLC
          std::cout << "HDLC" << '\n';
          break;

        case 0x0805: // STP (Spanning Tree Protocol)
          std::cout << "STP" << '\n';
          break;


        case 0x0806: // Address Resolution Protocol (ARP)
          std::cout << "ARP" << '\n';
          break;


        case 0x8100: // VLAN Tag
          std::cout << "Next Header Will Be VLAN Tag" << '\n';
          break;


        case 0x86dd: // IPv6
          std::cout << "IPv6" << '\n';
          break;


        default:
          std::cout << "Unknown" << '\n';
          Spotlight::unknown++;
          break;

      }

      Spotlight::outETH(eth->h_proto, eth->h_source, eth->h_dest);
      Spotlight::processIPH(inData);
      // Spotlight::outCounters();

    }

    static void processIPH(unsigned char* inData){
      // IP Header
      struct iphdr *iph = (struct iphdr*)(inData + sizeof(struct ethhdr));

      Spotlight::outIPH(iph);

      switch(iph->protocol){
        case 1: // ICMP
          Spotlight::ICMP++;
          break;

        case 2: // IGMP
          Spotlight::IGMP++;
          break;

        case 6: // TCP
          Spotlight::TCP++;
          Spotlight::outTCPH(inData);

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

      // delete iph;

    }

    ////// Outs
    static void outETH(int protocol, unsigned char source[6], unsigned char destination[6]){
      std::cout << "\n---------------------- outETH ----------------------" << '\n';

      // Source Address
      std::cout << "Source Address: ";
      Spotlight::loopETHAdresses(source);

      // Destination Address
      std::cout << "Destination Address: ";
      Spotlight::loopETHAdresses(destination);

      // Protocol
      std::cout << "Protocol: " << protocol << '\n';

    }

    static void outIPH(struct iphdr *iph){
      std::cout << "\n---------------------- outIPH ----------------------" << '\n';


      std::cout << "IP Version: " << (unsigned int)iph->version << '\n';

      std::cout << "Protocol: " << (unsigned int)iph->protocol << '\n';

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

      // delete iph;

    }

    static void outTCPH(unsigned char* inData){
      struct iphdr *iph = (struct iphdr*)(inData + sizeof(struct ethhdr));
      struct tcphdr *tcph = (struct tcphdr *)(inData + sizeof(struct ethhdr) + sizeof(struct iphdr));

      std::cout << "\n---------------------- outTCPH ----------------------" << '\n';

      std::cout << "TCP Header" << '\n';
      std::cout << "Source Port: " << ntohs(tcph->source) << '\n';
      std::cout << "Destination Port: " << ntohs(tcph->dest) << '\n';
      std::cout << "Sequence Number: " << ntohl(tcph->seq) << '\n';
      std::cout << "Acknowledge Number: " << ntohl(tcph->ack_seq) << '\n';
      std::cout << "Header Length: " << tcph->doff*4 << " bytes" << '\n';
      std::cout << "Window Size: " << ntohs(tcph->window) << '\n';
      std::cout << "Checksum: " << ntohs(tcph->check) << '\n';
      std::cout << "Urgent Pointer: " << tcph->urg_ptr << '\n';

      // TCP Payload
      int tcp_header_len = tcph->doff*4;
      int payload_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - tcp_header_len;
      unsigned char* payload = inData + sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_header_len;
      std::cout << "Payload: " << payload << '\n';

    }

    static void outCounters(){
      std::cout
      << "\x1b[2J"    // Clear Entire Terminal
      << "\x1b[1;1f"  // Move Cursor To 1:1
      << "ICMP: "       << Spotlight::ICMP
      << "\nIGMP: "     << Spotlight::IGMP
      << "\nTCP: "      << Spotlight::TCP
      << "\nEGP: "      << Spotlight::EGP
      << "\nUDP: "      << Spotlight::UDP

      // << "\nIPv4: "      << Spotlight::IPv4
      // << "\nIPv6: "      << Spotlight::IPv6
      // << "\nRAW: "      << Spotlight::RAW
      // << "\nRDP: "      << Spotlight::RDP
      // << "\nRTP: "      << Spotlight::RTP
      // << "\nSSL: "      << Spotlight::SSL
      // << "\nTLS: "      << Spotlight::TLS
      // << "\nLLDP: "      << Spotlight::LLDP
      // << "\nSTP: "      << Spotlight::STP
      // << "\nARP: "      << Spotlight::ARP
      // << "\nMAC_Security: "      << Spotlight::MAC_Security
      // << "\nPTP: "      << Spotlight::PTP
      // << "\nVLAN: "      << Spotlight::VLAN

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

    static void loopETHAdresses(unsigned char addresses[6]){
      for(std::size_t i = 0; i < 6; i++){
        std::cout
          << Spotlight::intToString(addresses[i])
          << ((i != 5) ? '-' : '\n');
      }

    }

    static void brand(){
      std::cout
        << "\x1b[2J"              // Clear Entire Terminal
        << "\x1b[1;1f"            // Move Cursor To 1:1
        << "\033[1;40;36m"        // FG Color
        << "--- Spotlight ---"
        << "\x1b[0m"              // Reset Color
        << '\n';

    }

    ///////// Variables
    // Counters
    static int total, unknown;
    static int ICMP, IGMP, TCP, EGP, UDP;

    static int IPv4, IPv6, RAW, RDP, RTP, SSL, TLS, LLDP, STP, ARP, MAC_Security, PTP, VLAN;

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

  // int Spotlight::IPv4 = 0;
  // int Spotlight::IPv6 = 0;
  // int Spotlight::RAW = 0;
  // int Spotlight::RDP = 0;
  // int Spotlight::RTP = 0;
  // int Spotlight::SSL = 0;
  // int Spotlight::TLS = 0;
  // int Spotlight::LLDP = 0;
  // int Spotlight::STP = 0;
  // int Spotlight::ARP = 0;
  // int Spotlight::MAC_Security = 0;
  // int Spotlight::PTP = 0;
  // int Spotlight::VLAN = 0;


  int Spotlight::fd_socket = -1;
  int Spotlight::bytes_received = 0;
  int Spotlight::BUFFER_SIZE = 262144; // 256kb

}

#endif
