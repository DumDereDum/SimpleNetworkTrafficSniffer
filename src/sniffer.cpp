#include "sniffer.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

void writePacketToFile(std::ofstream& outputFile, const std::vector<char>& packet, const char* src_ip, const char* dest_ip, const IPV4_HDR* ip_hdr) {
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
    outputFile.write(packet.data(), packet.size());
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


void packetWriter(std::ofstream& outputFile, std::queue<std::pair<std::vector<char>, std::string>>& packetQueue, std::mutex& queueMutex, std::condition_variable& cv, bool& done) {
    while (!done || !packetQueue.empty()) {
        std::unique_lock<std::mutex> lock(queueMutex);
        cv.wait(lock, [&]() { return !packetQueue.empty() || done; });
        while (!packetQueue.empty()) {
            auto packetData = packetQueue.front();
            packetQueue.pop();
            lock.unlock();
            auto packet = packetData.first;
            auto info = packetData.second;
            outputFile << info << " ";
            for (const auto& byte : packet) {
                outputFile << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned int>(static_cast<unsigned char>(byte))) << "";
            }
            outputFile << std::endl;
            lock.lock();
        }
    }
}

void packetReader(const std::string& filename, std::mutex& queueMutex, std::condition_variable& cv, bool& done) {
    char ch;
    std::string filter = "";
    int filter_column = 0;
    int start_index = 0;
    const int max_display = 30;
    while (true) {
        std::vector<Packet> packets = read_packets_from_file(filename);

        if (packets.size() > 30) {
            packets.resize(30);
        }

        std::cout << "\nEnter column number to filter (1-4), 'r' to reset, 'u' to scroll up, 'd' to scroll down, or 'q' to quit: ";
        std::cin >> ch;
        if (ch == 'q' || ch == 'Q') {
            break;
        }
        else if (ch == 'r' || ch == 'R') {
            filter = "";
            filter_column = 0;
            start_index = 0;
            display_packets(packets, filter, filter_column, start_index, max_display);
            continue;
        }
        else if (ch == 'u' || ch == 'U') {
            if (start_index > 0) {
                start_index -= max_display;
                if (start_index < 0) start_index = 0;
                display_packets(packets, filter, filter_column, start_index, max_display);
            }
            else
                display_packets(packets, filter, filter_column, start_index, max_display);
            std::cout << "Reached the start of packet list." << std::endl;

            continue;
        }
        else if (ch == 'd' || ch == 'D') {
            if (start_index + max_display < packets.size()) {
                start_index += max_display;
                display_packets(packets, filter, filter_column, start_index, max_display);
            }
            else {
                display_packets(packets, filter, filter_column, start_index, max_display);
                std::cout << "Reached the end of packet list." << std::endl;
            }
            continue;
        }

        switch (ch) {
        case '1':
            filter_column = 1;
            break;
        case '2':
            filter_column = 2;
            break;
        case '3':
            filter_column = 3;
            break;
        case '4':
            filter_column = 4;
            break;
        default:
            std::cout << "Invalid column number!" << std::endl;
            continue;
        }

        if (filter_column > 0) {
            std::cout << "Enter filter for column " << filter_column << ": ";
            std::cin.ignore();
            std::getline(std::cin, filter);
            try {
                start_index = 0;
                display_packets(packets, filter, filter_column, start_index, max_display);
            }
            catch (const std::regex_error& e) {
                std::cout << "Regex error: " << e.what() << std::endl;
            }
        }
    }
}


std::string get_field(const Packet& packet, int filter_column) {
    switch (filter_column) {
    case 0: return packet.time;
    case 1: return packet.src;
    case 2: return packet.dst;
    case 3: return packet.type;
    case 4: return packet.ttl;
    case 5: return packet.size;
    case 6: return packet.data;
    default: return "";
    }
}

#ifdef _WIN32
#include <windows.h>
#else
#include <cstdlib>
#endif

void clear_screen() {
#ifdef _WIN32
    HANDLE hStdOut;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count;
    DWORD cellCount;
    COORD homeCoords = { 0, 0 };

    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdOut == INVALID_HANDLE_VALUE) return;

    if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(hStdOut, (TCHAR)' ', cellCount, homeCoords, &count)) return;
    if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;
    SetConsoleCursorPosition(hStdOut, homeCoords);
#else
    std::system("clear");
#endif
}

std::string decode_protocol_type(const std::string& type) {
    if (type == "1") return "ICMP";
    if (type == "6") return "TCP";
    if (type == "17") return "UDP";
    if (type == "89") return "OSPF";
    return type;
}

void display_packets(const std::vector<Packet>& packets, const std::string& filter, int filter_column, int start_index, int max_display) {
    clear_screen();

    std::cout << std::left
        << std::setw(12) << "Time(0)"
        << std::setw(20) << "Src(1)"
        << std::setw(20) << "Dst(2)"
        << std::setw(10) << "Type(3)"
        << std::setw(10) << "TTL(4)"
        << std::setw(10) << "Size(5)"
        << std::setw(50) << "Data(6)"
        << std::endl;
    std::cout << std::string(140, '-') << std::endl;

    std::regex pattern(filter);
    int displayed = 0;
    for (size_t i = start_index; i < packets.size() && displayed < max_display; ++i) {
        const auto& packet = packets[i];
        bool match = filter_column ? std::regex_search(get_field(packet, filter_column), pattern) : true;
        if (match) {
            std::string trimmed_data = packet.data.substr(0, 45);
            std::cout << std::left
                << std::setw(12) << packet.time
                << std::setw(20) << packet.src
                << std::setw(20) << packet.dst
                << std::setw(10) << decode_protocol_type(packet.type)
                << std::setw(10) << packet.ttl
                << std::setw(10) << packet.size
                << std::setw(45) << trimmed_data
                << std::endl;
            ++displayed;
        }
    }
}

std::vector<Packet> read_packets_from_file(const std::string& filename) {
    std::vector<Packet> packets;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return packets;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        Packet packet;
        if (!(iss >> packet.time >> packet.src >> packet.dst >> packet.ttl >> packet.type >> packet.size >> packet.data)) {
            std::cerr << "Error reading packet from line: " << line << std::endl;
            continue;
        }
        if (!packet.data.empty() && packet.data[0] == ' ') {
            packet.data.erase(0, 1);
        }
        packets.push_back(packet);
    }

    file.close();
    return packets;
}
