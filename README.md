# Analizer
Script en Python que analiza logs de servidores web para detectar intentos de ataque como SQL Injection, XSS y Fuerza Bruta. Bloquea automáticamente las IPs sospechosas y permite desbloquearlas manualmente.
# 🛡️ Analizador de Logs - Detección de Ataques

Este script analiza archivos de logs en busca de intentos de ataque contra un servidor web, detectando técnicas como SQL Injection, Fuerza Bruta, XSS, Escaneo de Directorios, entre otros. Además, bloquea las IPs que realicen múltiples intentos maliciosos.

## Características
- **Detecta ataques** como SQL Injection, XSS, Path Traversal, Fuerza Bruta, etc.
- **Bloquea IPs** con múltiples intentos y las guarda en `banned_ips.txt`.
- **Formato mejorado** con colores y tablas para visualizar mejor los resultados.
- **Permite desbloquear IPs** eliminándolas del archivo `banned_ips.txt`.

## Instalación

```bash
# Clona el repositorio
git clone https://github.com/retr0-bit011/analizador-logs.git
cd analizador-logs

## Uso

```bash
python3 analizador_logs.py test.log
```

## Archivo de bloqueo de IPs

Si una IP comete múltiples intentos de ataque, será añadida a `banned_ips.txt`. Para desbloquearla, simplemente elimínala de ese archivo.



