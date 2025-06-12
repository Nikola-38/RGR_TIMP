import nmap

import os
import platform
import ipaddress
import logging
import subprocess
from flask import Flask, render_template
import platform

app = Flask(__name__)

def is_host_reachable(target):
    response = os.system(f"ping -c 1 {target}")  # Для Linux
    # response = os.system(f"ping -n 1 {target}")  # Для Windows
    return response == 0

def scan_ports(target):
    if is_host_reachable(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sT')  # Используем TCP Connect
        open_ports = []

        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                lport = nm[target][proto].keys()
                for port in lport:
                    if nm[target][proto][port]['state'] == 'open':
                        open_ports.append(port)
        
        # Возвращаем список открытых портов (может быть пустым)
        return open_ports
    else:
        # Хост недоступен, возвращаем пустой список
        return []


def scan_network(subnet):
    # старая версия функции
    active_devices = []
    hosts = list(ipaddress.ip_network(subnet).hosts())
    for host in hosts:
        ip = str(host)
        if not ip.startswith("127."):
            if is_host_reachable(ip):
                active_devices.append(ip)
    return active_devices


def scan_network_verbose(subnet):
    active_devices = []
    all_devices_status = {}

    # Определение команды ping в зависимости от ОС
    if platform.system() == "Windows":
        base_ping_cmd = ["ping", "-n", "1", "-w", "100"]
    else:
        base_ping_cmd = ["ping", "-c", "1", "-W", "1"]

    # Преобразуем строку в подсеть, если это необходимо
    if isinstance(subnet, str):
        try:
            subnet = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logging.error(f"Неверный формат подсети: {subnet}")
            return [], {}

    hosts = list(subnet.hosts())
    logging.info(f"Сканируем подсеть {subnet} ({len(hosts)} хостов)")

    for host in hosts:
        ip = str(host)
        if ip.startswith("127."):
            continue  # Пропускаем loopback

        ping_cmd = base_ping_cmd + [ip]
        try:
            result = subprocess.run(
                ping_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            is_online = result.returncode == 0
            status = "Доступен" if is_online else "Недоступен"
        except Exception as e:
            is_online = False
            status = f"Ошибка: {e}"

        logging.info(f"{ip} — {status}")
        all_devices_status[ip] = status

        if is_online:
            active_devices.append(ip)

    return active_devices, all_devices_status

if __name__ == "__main__":
    app.run(debug=True)
