import socket
import ipaddress
import argparse
import concurrent.futures
import csv
import logging
from scapy.all import ARP, Ether, srp
import nmap
from colorama import init, Fore

# Inicializar colorama para resaltar los resultados en la consola
init(autoreset=True)

# Configurar el sistema de registro
logging.basicConfig(filename="scan_ip.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def validate_cidr(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_port_list(ports):
    try:
        port_list = [int(port) for port in ports.split(",")]
        return all(0 <= port <= 65535 for port in port_list)
    except ValueError:
        return False

def scan_ip(ip):
    try:
        host = socket.gethostbyaddr(str(ip))
        return ip, host[0]
    except socket.herror:
        return None

def scan_ips(network_cidr, start_ip=None, end_ip=None, output_file=None):
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        print("El formato del prefijo de red no es válido.")
        return

    found_hosts = False
    results = []

    if not start_ip:
        start_ip = network.network_address
    if not end_ip:
        end_ip = network.broadcast_address

    with concurrent.futures.ThreadPoolExecutor() as executor:
        ip_range = range(int(start_ip), int(end_ip) + 1)
        futures = [executor.submit(scan_ip, ipaddress.IPv4Address(ip)) for ip in ip_range]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(Fore.GREEN + "Host encontrado: {} - {}".format(result[0], result[1]))
                logging.info("Host encontrado: {} - {}".format(result[0], result[1]))
                results.append(result)
                found_hosts = True

    if not found_hosts:
        print("No se ha detectado ningún host.")
        logging.info("No se ha detectado ningún host.")

    if output_file:
        with open(output_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["IP", "Host"])
            csv_writer.writerows(results)

def detect_active_devices(ip_range, interface="auto"):
    if interface == "auto":
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        if len(interfaces) > 0:
            interface = interfaces[0]
        else:
            print("No se pudo detectar una interfaz de red activa.")
            return

    print("Detectando dispositivos activos en la red utilizando la interfaz {}...".format(interface))

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0, iface=interface)

    active_devices = []
    for sent, received in result[0]:
        active_devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return active_devices

def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, ports=ports)
    
    open_ports = []
    for port in nm[ip]["tcp"]:
        if nm[ip]["tcp"][port]["state"] == "open":
            open_ports.append(port)
    
    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramienta de escaneo y análisis de IPs en red.")
    parser.add_argument("network_cidr", type=str, help="Prefijo de red con máscara (ejemplo: 192.168.1.0/24)")
    parser.add_argument("--start_ip", type=str, help="Dirección IP de inicio (opcional)")
    parser.add_argument("--end_ip", type=str, help="Dirección IP de fin (opcional)")
    parser.add_argument("--output_file", type=str, help="Archivo de salida para guardar los resultados (opcional)")
    parser.add_argument("--detect_active", action="store_true", help="Detectar dispositivos activos en la red")
    parser.add_argument("--interface", type=str, default="auto", help="Interfaz de red para la detección de dispositivos (opcional)")
    parser.add_argument("--scan_ports", type=str, help="Escaneo de puertos abiertos en una IP específica (formato: IP:puerto,puerto,...)")

    args = parser.parse_args()

    if not validate_cidr(args.network_cidr):
        print("El formato del prefijo de red no es válido.")
    else:
        if args.detect_active:
            active_devices = detect_active_devices(args.network_cidr, args.interface)
            print("Dispositivos activos encontrados:")
            for device in active_devices:
                print("IP: {}, MAC: {}".format(device["ip"], device["mac"]))

        if args.scan_ports:
            ip, ports = args.scan_ports.split(":")
            if validate_port_list(ports):
                open_ports = scan_ports(ip, ports)
                if open_ports:
                    print("Puertos abiertos en {}: {}".format(ip, ", ".join(map(str, open_ports))))
                else:
                    print("No se encontraron puertos abiertos en {}.".format(ip))
            else:
                print("El formato de los puertos no es válido.")

        scan_ips(args.network_cidr, args.start_ip, args.end_ip, args.output_file)
