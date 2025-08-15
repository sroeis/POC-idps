#include <pcap.h>  
#include <iostream>  
#include <iomanip>  
#include <winsock2.h> // for ntohs, ntohl on Windows  
#include <ws2tcpip.h> // for inet_ntop  

#pragma comment(lib, "wpcap.lib")  
#pragma comment(lib, "Packet.lib")  
#pragma comment(lib, "ws2_32.lib") // for inet_ntop  

struct ethernet_header {  
   u_char dest[6];  
   u_char src[6];  
   u_short type;  
};  

struct ip_header {  
   u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)  
   u_char  tos;            // Type of service   
   u_short tlen;           // Total length   
   u_short identification; // Identification  
   u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)  
   u_char  ttl;            // Time to live  
   u_char  proto;          // Protocol  
   u_short crc;            // Header checksum  
   struct  in_addr saddr;  // Source address  
   struct  in_addr daddr;  // Destination address  
};  

struct tcp_header {  
   u_short sport; // Source port  
   u_short dport; // Destination port  
   u_int   seqnum;  
   u_int   acknum;  
   u_char  data_offset; // Data offset, reserved bits  
   u_char  flags;  
   u_short window;  
   u_short checksum;  
   u_short urgent;  
};  

struct udp_header {  
   u_short sport; // Source port  
   u_short dport; // Destination port  
   u_short len;  
   u_short crc;  
};  

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {  
   const ethernet_header* eth = (ethernet_header*)packet;  

   // Only process IPv4 packets (0x0800)  
   if (ntohs(eth->type) != 0x0800) return;  

   const ip_header* ip = (ip_header*)(packet + sizeof(ethernet_header));  
   int ipHeaderLen = (ip->ver_ihl & 0x0F) * 4;  

   char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];  
   inet_ntop(AF_INET, &(ip->saddr), srcIP, INET_ADDRSTRLEN);  
   inet_ntop(AF_INET, &(ip->daddr), dstIP, INET_ADDRSTRLEN);  

   if (ip->proto == 6) { // TCP  
       const tcp_header* tcp = (tcp_header*)((u_char*)ip + ipHeaderLen);  
       std::cout << "TCP  " << srcIP << ":" << ntohs(tcp->sport)  
           << " -> " << dstIP << ":" << ntohs(tcp->dport) << "\n";  
   }  
   else if (ip->proto == 17) { // UDP  
       const udp_header* udp = (udp_header*)((u_char*)ip + ipHeaderLen);  
       std::cout << "UDP  " << srcIP << ":" << ntohs(udp->sport)  
           << " -> " << dstIP << ":" << ntohs(udp->dport) << "\n";  
   }  
   else {  
       std::cout << "IP   " << srcIP << " -> " << dstIP << " (proto " << (int)ip->proto << ")\n";  
   }  
}  

int main() {  
   char errbuf[PCAP_ERRBUF_SIZE];  
   pcap_if_t* alldevs;  

   if (pcap_findalldevs(&alldevs, errbuf) == -1) {  
       std::cerr << "Error finding devices: " << errbuf << "\n";  
       return 1;  
   }  

   int i = 0;  
   pcap_if_t* d;  
   for (d = alldevs; d != nullptr; d = d->next) {  
       std::cout << ++i << ": " << d->name;  
       if (d->description) std::cout << " (" << d->description << ")";  
       std::cout << "\n";  
   }  

   if (i == 0) {  
       std::cout << "No interfaces found.\n";  
       return 1;  
   }  

   int choice;  
   std::cout << "Enter interface number: ";  
   std::cin >> choice;  

   if (choice < 1 || choice > i) {  
       std::cerr << "Invalid choice.\n";  
       return 1;  
   }  

   d = alldevs;  
   for (int j = 1; j < choice; j++) {  
       d = d->next;  
   }  

   pcap_t* handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);  
   if (!handle) {  
       std::cerr << "Couldn't open device: " << errbuf << "\n";  
       pcap_freealldevs(alldevs);  
       return 1;  
   }  

   std::cout << "Capturing on " << d->name << "...\n";  
   pcap_loop(handle, 0, packetHandler, nullptr);  

   pcap_close(handle);  
   pcap_freealldevs(alldevs);  

   return 0;  
}
