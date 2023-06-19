import random
import socket
import sys
import requests
import traceback

# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# setam timeout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(3)

# Funcția pentru a obține informații despre locația unui IP
def get_location(ip):
    fake_HTTP_header = {
        'referer': 'https://ipinfo.io/',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
    }
    api_key = "7d4a4802625d58"
    url = f"https://ipinfo.io/{ip}?token={api_key}"
    response = requests.get(url, headers = fake_HTTP_header)
    data = response.json()
    return data

# Funcția pentru traceroute
def traceroute(ip, port):
    n_hops = 30
    for i in range (1, n_hops + 1):
        # setam TTL in headerul de IP pentru socketul de UDP
        TTL = i
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)

        # trimite un mesaj UDP catre un tuplu (IP, port)
        udp_send_sock.sendto(b'salut', (ip, port))

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        # verificam daca primul byte are valoarea Type == 11

        # addr = 'done!'
        try:
            data, addr = icmp_recv_socket.recvfrom(63535)
            # tipul pt icmp incepe la byte-ul 20
            # if data[20] != 11:
            #     break

        except Exception as e:
            print("Socket timeout ", str(e))
            # print(traceback.format_exc())
            continue

        # generam doar adresa IP a routerului
        yield addr[0]

        # verificam daca am ajuns la destinatie
        if addr[0] == ip:
            break

# extragem numele site-ului si obtinem ip-ul
name = sys.argv[1]
host = socket.gethostbyname(name)

directions = []

with open("traceroutes.txt", "a") as file:
    file.seek(0, 2)

    print(host + " - " + get_location(host)['country'])
    file.write(host + " - " + get_location(host)["country"] + "\n")

    i = 1
    for ip in traceroute(host, random.randint(33434, 33534)):
        ip_location = get_location(ip)

        # verificam daca avem informatiile necesare sau adresa este privata
        if 'city' in ip_location:
            print(str(i) + ". " + ip + " - " + "City: " + ip_location["city"] + ", Region: " + ip_location["region"] + ", Country: " + ip_location["country"])
            file.write(str(i) + ". " + ip + " - " + "City: " + ip_location["city"] + ", Region: " + ip_location["region"] + ", Country: " + ip_location["country"] + '\n')
            
            # memoram latitudine si longitudinea fiecarui hop pentru a face un plot cu traseul mesajului
            directions.append(ip_location["loc"])
        else:
            print(str(i) + ". " + ip + " - " + "Private address")
            file.write(str(i) + ". " + ip + " - " + "Private address\n")
        i += 1

    file.write("\n")
    
print(directions)