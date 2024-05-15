#include "sniffer.h"
#include <iostream>
#include <queue>
#include <sstream>
#include <iomanip>
#include <chrono>

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

    std::queue<std::pair<std::vector<char>, std::string>> packetQueue;
    std::mutex queueMutex;
    std::condition_variable cv;
    bool done = false;

    // Start writer thread
    std::thread writerThread(packetWriter, std::ref(outputFile), std::ref(packetQueue), std::ref(queueMutex), std::ref(cv), std::ref(done));

    // Start reader thread
    std::thread readerThread(packetReader, std::ref(packetQueue), std::ref(queueMutex), std::ref(cv), std::ref(done));

    // Buffer for incoming data
    char buffer[65535];
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    IPV4_HDR* ip_hdr;
    int packetSize;

    while (true) {
        if (receivePacket(sock, buffer, sizeof(buffer), src_ip, dest_ip, ip_hdr, packetSize)) {
            std::vector<char> packet(buffer, buffer + packetSize);

            // Generate packet info string
            std::ostringstream info;
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            info << std::put_time(std::localtime(&now_c), "%T") << " ";
            info << src_ip << " ";
            info << dest_ip << " ";
            info << (int)ip_hdr->ip_ttl << " ";
            info << (int)ip_hdr->ip_protocol << " ";
            info << ip_hdr->ip_total_length;

            std::unique_lock<std::mutex> lock(queueMutex);
            packetQueue.emplace(packet, info.str());
            lock.unlock();
            cv.notify_one();
        }
    }

    // Signal writer and reader threads to finish
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        done = true;
    }
    cv.notify_all();

    writerThread.join();
    readerThread.join();

    closesocket(sock);
    WSACleanup();
    outputFile.close();
    return 0;
}
