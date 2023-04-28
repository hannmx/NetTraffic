from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import *
import scapy.arch
import time
import threading

# создание списка для хранения временных меток и количества захваченных пакетов
packet_count = []
timestamps = []

interfaces = scapy.arch.get_if_list()

# функция, которая будет вызываться для каждого перехваченного пакета
def handle_packet(packet):
    # извлечь заголовок Ethernet
    eth = packet[Ether]
    eth_protocol = eth.type

    # если это IP-пакет
    if eth_protocol == 0x0800:
        # извлечь заголовок IP
        iph = packet[IP]
        protocol = iph.proto
        s_addr = iph.src
        d_addr = iph.dst

        # если это TCP-пакет
        if protocol == 6:
            # извлечь заголовок TCP
            tcph = packet[TCP]
            source_port = tcph.sport
            dest_port = tcph.dport
            sequence = tcph.seq
            acknowledgement = tcph.ack
            tcph_length = tcph.dataofs
            packet_length = len(packet)

            # вывести информацию о пакете
            print('Source IP: ' + str(s_addr) + ' Destination IP: ' + str(d_addr) +
                  ' Source Port: ' + str(source_port) + ' Destination Port: ' + str(dest_port) +
                  ' Sequence: ' + str(sequence) + ' Acknowledgement: ' + str(acknowledgement) +
                  ' TCP header length: ' + str(tcph_length))

            # записать информацию о пакете в файл
            with open("sniffer_output.txt", "a") as f:
                f.write(f"Source IP: {s_addr} Source Port: {source_port} Destination IP: {d_addr} Destination Port: {dest_port} Packet Length: {packet_length}\n")

# начать сниффинг сетевого трафика на выбранном интерфейсе
stop_sniffing = False

def stop_capture():
    global stop_sniffing
    time.sleep(5)
    stop_sniffing = True

thread = threading.Thread(target=stop_capture)
thread.start()

# определение выбора пользователя для использования фильтра или нет
use_filter = input("Использовать фильтр? (y/n): ")
if use_filter.lower() == "y":
    # задать фильтр для сниффера
    filter_str = input("Введите строку фильтрации: ")
    sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet, filter=filter_str)
else:
    sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet)
    
sniffer.start()

while not stop_sniffing:
    time.sleep(1)

sniffer.stop_sniffing()