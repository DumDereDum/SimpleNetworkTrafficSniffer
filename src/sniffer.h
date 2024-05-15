#ifndef SNIFFER_H
#define SNIFFER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#pragma comment(lib, "ws2_32.lib") // Link with the Ws2_32.lib library

typedef struct ip_hdr {
    unsigned char  ip_header_len : 4;  // IP header length
    unsigned char  ip_version : 4;     // Version
    unsigned char  ip_tos;           // Type of service
    unsigned short ip_total_length;  // Total length
    unsigned short ip_id;            // Unique identifier
    unsigned short ip_frag_offset;   // Fragment offset
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol
    unsigned short ip_checksum;      // Checksum
    struct in_addr  ip_srcaddr;      // Source address
    struct in_addr  ip_destaddr;     // Destination address
} IPV4_HDR;

void writePacketToFile(std::ofstream& outputFile, const std::vector<char>& packet, const char* src_ip, const char* dest_ip, const IPV4_HDR* ip_hdr);
bool receivePacket(SOCKET sock, char* buffer, int bufferSize, char* src_ip, char* dest_ip, IPV4_HDR*& ip_hdr, int& packetSize);
std::string generateFileName();
bool initializeWinsock(WSADATA& wsaData);
SOCKET createRawSocket();
bool bindSocket(SOCKET sock);

void packetWriter(std::ofstream& outputFile, std::queue<std::pair<std::vector<char>, std::string>>& packetQueue, std::mutex& queueMutex, std::condition_variable& cv, bool& done);
void packetReader(std::queue<std::pair<std::vector<char>, std::string>>& packetQueue, std::mutex& queueMutex, std::condition_variable& cv, bool& done);

#endif // SNIFFER_H
