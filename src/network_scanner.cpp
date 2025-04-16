#include "network_scanner.h"
#include "network_utils.h"
#include <iostream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <unordered_set>
#include <net/if.h>
#include <sys/ioctl.h>

NetworkScanner::NetworkScanner(const std::string& iface, const std::string& ip_addr)
    : interface(iface), ip(ip_addr) {}

std::vector<Device> NetworkScanner::scan() {
    std::vector<Device> devices;
    std::unordered_set<std::string> seen_ips;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error abriendo la interfaz: " << errbuf << std::endl;
        return devices;
    }

    std::string my_mac = get_mac_address(interface);
    std::string my_ip = get_ip_address(interface);

    // Convertir la MAC real a bytes
    uint8_t mac_bytes[6];
    sscanf(my_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);

    // Convertir IP propia a bytes
    in_addr src_ip_struct;
    inet_pton(AF_INET, my_ip.c_str(), &src_ip_struct);

    std::string base_ip = ip.substr(0, ip.rfind('.') + 1);

    for (int i = 1; i <= 254; ++i) {
        std::string target_ip = base_ip + std::to_string(i);
        if (target_ip == my_ip) continue;

        in_addr dst_ip_struct;
        inet_pton(AF_INET, target_ip.c_str(), &dst_ip_struct);

        uint8_t packet[42] = {0};

        // ===== Header Ethernet =====
        memset(packet, 0xff, 6);                   // dst MAC: broadcast ff:ff:ff:ff:ff:ff
        memcpy(packet + 6, mac_bytes, 6);          // src MAC: nuestra MAC
        packet[12] = 0x08;                         // Tipo: ARP
        packet[13] = 0x06;

        // ===== Header ARP =====
        packet[14] = 0x00; packet[15] = 0x01;       // Hardware type: Ethernet
        packet[16] = 0x08; packet[17] = 0x00;       // Protocol type: IPv4
        packet[18] = 0x06;                         // Hardware size: 6
        packet[19] = 0x04;                         // Protocol size: 4
        packet[20] = 0x00; packet[21] = 0x01;       // Opcode: request

        memcpy(packet + 22, mac_bytes, 6);         // ARP sender MAC
        memcpy(packet + 28, &src_ip_struct, 4);    // ARP sender IP
        memset(packet + 32, 0x00, 6);              // ARP target MAC: unknown
        memcpy(packet + 38, &dst_ip_struct, 4);    // ARP target IP

        if (pcap_sendpacket(handle, packet, 42) != 0) {
            std::cerr << "Error enviando ARP a " << target_ip << std::endl;
        }

        usleep(10000); // 10 ms entre paquetes
    }

    std::cout << "[*] Esperando respuestas..." << std::endl;

    time_t start = time(nullptr);
    while (time(nullptr) - start < 3) {  // 3 segundos para capturar respuestas
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if (ntohs(*(uint16_t*)(packet + 12)) != ETHERTYPE_ARP) continue;
        if (*(packet + 20) != 0x00 || *(packet + 21) != 0x02) continue; // ARP reply

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, packet + 28, sender_ip, sizeof(sender_ip));

        char sender_mac[18];
        snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 packet[22], packet[23], packet[24],
                 packet[25], packet[26], packet[27]);

        std::string ip_str(sender_ip);
        if (seen_ips.find(ip_str) == seen_ips.end()) {
            seen_ips.insert(ip_str);
            devices.push_back({ip_str, std::string(sender_mac)});
            std::cout << "[+] Dispositivo -> IP: " << ip_str << " | MAC: " << sender_mac << std::endl;
        }
    }

    pcap_close(handle);
    return devices;
}