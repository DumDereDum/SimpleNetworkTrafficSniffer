#include "sniffer.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

void writePacketToFile(std::ofstream& outputFile, const char* buffer, int size, const char* src_ip, const char* dest_ip, const IPV4_HDR* ip_hdr) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    struct tm local_time;
    localtime_s(&local_time, &now_c);

    // Write data to file
    outputFile << std::put_time(&local_time, "%T") << " ";
    outputFile << src_ip << " ";
    outputFile << dest_ip << " ";
    outputFile << (int)ip_hdr->ip_ttl << " ";
    outputFile << (int)ip_hdr->ip_protocol << " ";
    outputFile << ip_hdr->ip_total_length << " ";
    outputFile.write(buffer, size);
    outputFile << std::endl;
}

bool receivePacket(SOCKET sock, char* buffer, int bufferSize, char* src_ip, char* dest_ip, IPV4_HDR*& ip_hdr, int& packetSize) {
    memset(buffer, 0, bufferSize);
    packetSize = recv(sock, buffer, bufferSize, 0);
    if (packetSize == SOCKET_ERROR) {
        std::cerr << "Recv failed with error: " << WSAGetLastError() << std::endl;
        return false;
    }

    // Parse the packet
    ip_hdr = (IPV4_HDR*)buffer;
    if (inet_ntop(AF_INET, &(ip_hdr->ip_srcaddr), src_ip, INET_ADDRSTRLEN) == NULL ||
        inet_ntop(AF_INET, &(ip_hdr->ip_destaddr), dest_ip, INET_ADDRSTRLEN) == NULL) {
        std::cerr << "inet_ntop failed with error: " << WSAGetLastError() << std::endl;
        return false;
    }
    if (strcmp(dest_ip, "127.0.0.1") == 0) {
        // Skip packet if destination address is 127.0.0.1
        return false;
    }
    return true;
}

std::string generateFileName() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    struct tm local_time;
    localtime_s(&local_time, &now_c);

    std::ostringstream oss;
    oss << "sniff_";
    oss << std::put_time(&local_time, "%Y%m%d_%H%M%S");
    oss << ".txt";
    return oss.str();
}

bool initializeWinsock(WSADATA& wsaData) {
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return false;
    }
    return true;
}

SOCKET createRawSocket() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
    }
    return sock;
}

bool bindSocket(SOCKET sock) {
    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces
    addr.sin_port = 0;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed with error: " << WSAGetLastError() << std::endl;
        return false;
    }
    return true;
}
