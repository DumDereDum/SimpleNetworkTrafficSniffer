#include "sniffer.h"
#include <iostream>

int main() {
    WSADATA wsaData;
    if (!initializeWinsock(wsaData)) {
        return 1;
    }

    SOCKET sock = createRawSocket();
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    if (!bindSocket(sock)) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::string fileName = generateFileName();
    std::ofstream outputFile(fileName, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to open output file" << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Writing to file: " << fileName << std::endl;

    char buffer[65535];
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    IPV4_HDR* ip_hdr;
    int packetSize;

    while (true) {
        if (receivePacket(sock, buffer, sizeof(buffer), src_ip, dest_ip, ip_hdr, packetSize)) {
            writePacketToFile(outputFile, buffer, packetSize, src_ip, dest_ip, ip_hdr);
        }
    }

    closesocket(sock);
    WSACleanup();
    outputFile.close();
    return 0;
}
