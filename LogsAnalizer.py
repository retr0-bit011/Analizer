import re
import argparse
from collections import defaultdict
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)
BANNED_IPS_FILE = "banned_ips.txt"

def detectar_ataques(linea):
    patrones = {
        "SQL Injection": r"(UNION.*SELECT|SELECT.*FROM|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM|DROP TABLE|--|#|/\*|\*/)",
        "Fuerza Bruta": r"(login|wp-login|admin).* 401",
        "Escaneo de Directorios": r"(/admin|/wp-login.php|/phpmyadmin|/login|/config|/setup).* 404",
        "XSS Attack": r"(<script>|javascript:|onerror=|onload=)",
        "Path Traversal": r"(\.\./|/etc/passwd|/etc/shadow|/proc/self/environ)",
        "Command Injection": r"(;|&&|\|\||`|\$\()",
        "User Agent Malicioso": r"(sqlmap|nmap|nikto|dirbuster|w3af|acunetix)"
    }
    
    for ataque, patron in patrones.items():
        if re.search(patron, linea, re.IGNORECASE):
            return ataque
    return None

def cargar_ips_bloqueadas():
    try:
        with open(BANNED_IPS_FILE, "r") as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        return set()

def guardar_ip_bloqueada(ip):
    with open(BANNED_IPS_FILE, "a") as f:
        f.write(ip + "\n")

def analizar_logs(archivo):
    reportes = defaultdict(int)
    intentos_por_ip = defaultdict(int)
    ips_bloqueadas = cargar_ips_bloqueadas()
    
    with open(archivo, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            partes = linea.split()
            if len(partes) < 1:
                continue
            ip = partes[0]
            if ip in ips_bloqueadas:
                continue
            
            ataque = detectar_ataques(linea)
            if ataque:
                reportes[ataque] += 1
                intentos_por_ip[ip] += 1
                if intentos_por_ip[ip] > 1:
                    guardar_ip_bloqueada(ip)
    
    return reportes

def imprimir_resultados(resultados):
    if resultados:
        print(Fore.CYAN + "\nResumen de ataques detectados:\n" + Style.RESET_ALL)
        
        tabla = [[Fore.RED + tipo + Style.RESET_ALL, cantidad] for tipo, cantidad in resultados.items()]
        print(tabulate(tabla, headers=[Fore.YELLOW + "Tipo de Ataque", Fore.YELLOW + "Cantidad" + Style.RESET_ALL], tablefmt="grid"))
    else:
        print(Fore.GREEN + "No se detectaron ataques sospechosos en el archivo de log." + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(description="Analizador de Logs para detectar ataques en servidores web")
    parser.add_argument("archivo", help="Ruta del archivo de log a analizar")
    args = parser.parse_args()
    
    resultados = analizar_logs(args.archivo)
    imprimir_resultados(resultados)

if __name__ == "__main__":
    main()
