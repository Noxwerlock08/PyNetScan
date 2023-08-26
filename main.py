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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramienta de escaneo de IPs en red.")
    parser.add_argument("network_cidr", type=str, help="Prefijo de red con máscara (ejemplo: 192.168.1.0/24)")
    parser.add_argument("--start_ip", type=str, help="Dirección IP de inicio (opcional)")
    parser.add_argument("--end_ip", type=str, help="Dirección IP de fin (opcional)")
    parser.add_argument("--output_file", type=str, help="Archivo de salida para guardar los resultados (opcional)")

    args = parser.parse_args()

    if not validate_cidr(args.network_cidr):
        print("El formato del prefijo de red no es válido.")
    else:
        scan_ips(args.network_cidr, args.start_ip, args.end_ip, args.output_file)
