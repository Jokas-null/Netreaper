#!/bin/bash

echo "[*] Compilando NetReaper..."

g++ -o netreaper \
    main.cpp \
    src/network_utils.cpp \
    src/network_scanner.cpp \
    src/arp_spoofer.cpp \
    src/traffic_control.cpp \
    src/gateway_utils.cpp \
    -Iinclude -lpcap

if [ $? -eq 0 ]; then
    echo "[✔] Compilación exitosa. Ejecutá con: sudo ./netreaper"
else
    echo "[✘] Error al compilar. Revisá el output arriba."
fi