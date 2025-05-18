import sys
import os
import time
from scapy.all import sniff, IP, TCP
import pandas as pd
from datetime import datetime
from collections import defaultdict

#Primero verificamos argumentos
if len(sys.argv) != 2:
    print("Uso: python pyids.py <tiempo_en_segundos>")
    sys.exit(1)

try:
    duracion = int(sys.argv[1])
except ValueError:
    print("Error: el argumento debe ser un número entero (segundos)")
    sys.exit(1)

print(f"[+] Capturando tráfico durante {duracion} segundos...")

#Creamos la carpeta /logs para guardar resultados
os.makedirs("logs", exist_ok=True)

#Declaro variables globales
eventos = []
registro_syn = defaultdict(list)
umbral_syn = 30   # Más de 30 SYN en 10 segundos

# Mapeo de puertos a servicios conocidos
puertos_servicios = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-alt"
}

#Declaro la funcion de analisis de paquetes
def analizar_paquete(pkt):
    if IP in pkt:  # Solo seguimos si el paquete realmente tiene una dirección IP (porque algunos paquetes pueden ser solo a nivel Ethernet, ARP, etc.)
        ip_origen = pkt[IP].src
        ip_destino = pkt[IP].dst  #Extraemos las IPs de origen y destino del paquete.
        proto = "TCP" if TCP in pkt else "UDP" if pkt.haslayer("UDP") else "Otro" #Esto determina si es un paquete TCP, UDP o "otro" (como ICMP)
        puerto_destino = pkt[TCP].dport if TCP in pkt else None
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        servicio = puertos_servicios.get(puerto_destino, "Desconocido")   #Si es TCP miramos a que puerto intenta conectarse y usamos el diccionario puertos_servivios

        alerta = None   # Creo variable para guardar una alerta si se detecta algo relevante

        # Detectar tráfico sospechoso o clasificado
        if TCP in pkt and pkt[TCP].flags == "S":   #Detecta si es un paquete con flag SYN activado (intento de establecer conexión), Como con Nmap
            registro_syn[ip_origen].append(datetime.now())
            registro_syn[ip_origen] = [
                t for t in registro_syn[ip_origen]
                if (datetime.now() - t).total_seconds() < 10
            ]
            if len(registro_syn[ip_origen]) > umbral_syn:
                alerta = f"SYN Flood detectado ({len(registro_syn[ip_origen])} SYNs en 10s)"
            else:
                alerta = "Conexión TCP (SYN)"  # Guardar cada intento SYN que viene de una IP. Mantener solo los últimos 10 segundos.Si hay más de 30 en ese tiempo probable ataque de SYN Flood

        elif servicio != "Desconocido":
            alerta = f"Tráfico identificado como {servicio}"  #Si no es un SYN, pero va a un puerto conocido

        if alerta:
            eventos.append({
                "timestamp": timestamp,
                "source_ip": ip_origen,
                "dest_ip": ip_destino,
                "protocol": proto,
                "service": servicio,
                "alert": alerta
            })   #Guardamos todos los datos relevantes en un diccionario y lo añadimos a la lista eventos que luego exportaremos al CSV.

#Captura de tráfico
sniff(timeout=duracion, prn=analizar_paquete, store=0)

# Guardar resultados
df = pd.DataFrame(eventos)
nombre_archivo = f"logs/ids_resultado_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
df.to_csv(nombre_archivo, index=False)

print(f"[✔] Captura finalizada. Resultados guardados en: {nombre_archivo}")