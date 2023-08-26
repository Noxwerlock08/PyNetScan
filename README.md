# Herramienta de Escaneo y Análisis de IPs en Red

Esta es una herramienta de línea de comandos desarrollada en Python que te permite escanear y analizar IPs en una red. Proporciona varias funcionalidades, como el escaneo de IPs, la detección de dispositivos activos y el escaneo de puertos abiertos.

## Requisitos

- Python 3.x
- Pip (administrador de paquetes de Python)

## Instalación
Descargar el repositorio de Github:
```
git clone https://github.com/Noxwerlock08/Python-Scanner.git
```

Dale el permiso a los archivos:
```bash
chmod +x *
```

Instala las dependencias necesarias ejecutando el archivo `install.sh`
```bash
./install.sh
```

## Uso
Ejecuta el código desde la línea de comandos siguiendo las instrucciones a continuación:

```bash
python3 main.py <network_cidr> [--start_ip <start_ip>] [--end_ip <end_ip>] [--output_file <output_file>] [--detect_active] [--interface <interface>] [--scan_ports <ip:ports>]
```

Opciones Obligatorias
* <network_cidr>: Prefijo de red con máscara (por ejemplo, 192.168.1.0/24).

Opciones Opcionales
* --start_ip: Dirección IP de inicio del rango.
* --end_ip: Dirección IP de fin del rango.
* --output_file: Archivo de salida para guardar los resultados en formato CSV.
* --detect_active: Detecta dispositivos activos en la red.
* --interface: Interfaz de red para la detección de dispositivos (por defecto: auto).
* --scan_ports: Escaneo de puertos abiertos en una IP específica (formato: IP:puerto,puerto,...).

Ejemplos de Uso
* Escanear IPs en la red 192.168.1.0/24 y guardar los resultados en un archivo CSV:

```bash
python3 main.py 192.168.1.0/24 --output_file results.csv
```

Detectar dispositivos activos en la red:
```bash
python3 main.py 192.168.1.0/24 --detect_active
```

Escanear puertos abiertos en una IP específica:

```bash
python3 main.py 192.168.1.100 --scan_ports 192.168.1.100:80,443
```

Notas Importantes
Asegúrate de tener los permisos necesarios para ejecutar la detección de dispositivos activos y el escaneo de puertos.
La opción --interface utiliza "auto" para detectar automáticamente una interfaz de red activa. Puedes especificar una interfaz manualmente si lo deseas.
Contribuciones
Las contribuciones son bienvenidas. Si encuentras algún error, tienes ideas para mejoras o funcionalidades adicionales, siéntete libre de realizar un pull request.

Licencia
Este proyecto está bajo la Licencia MIT. Ver el archivo LICENSE para más detalles.
