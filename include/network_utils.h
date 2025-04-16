#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <string>

// Devuelve la interfaz de red activa (eth0, wlan0, etc.)
std::string get_active_interface();

// Devuelve la dirección IP del equipo
std::string get_ip_address(const std::string& interface);

// Devuelve la dirección MAC del equipo
std::string get_mac_address(const std::string& interface);

#endif // NETWORK_UTILS_H