import tkinter as tk
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import *
import scapy.arch
import time
import threading

# функция для обработки события нажатия кнопки "Start"
def start_sniffing():
    global stop_sniffing, sniffer, use_filter_var, filter_var
    stop_sniffing = False
    
    use_filter = use_filter_var.get()
    if use_filter:
        # задать фильтр для сниффера
        filter_str = filter_var.get()
        sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet, filter=filter_str)
    else:
        sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet)
    
    sniffer.start()

# функция для обработки события нажатия кнопки "Stop"
def stop_sniffing_func():
    global stop_sniffing, sniffer
    stop_sniffing = True
    if 'sniffer' in globals():
        sniffer.stop()

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
            packet_info = f'Source IP: {s_addr} Destination IP: {d_addr} ' \
                          f'Source Port: {source_port} Destination Port: {dest_port} ' \
                          f'Sequence: {sequence} Acknowledgement: {acknowledgement} ' \
                          f'TCP header length: {tcph_length}'
            print(packet_info)

            # записать информацию о пакете в файл
            with open("sniffer_output.txt", "a") as f:
                f.write(f"{packet_info}\n")

# создание GUI
root = tk.Tk()
root.title("Packet Sniffer")

# создание метки и поля ввода для фильтра
use_filter_var = tk.BooleanVar()
use_filter_var.set(False)
use_filter_checkbutton = tk.Checkbutton(root, text="Use Filter", variable=use_filter_var)
use_filter_checkbutton.grid(row=0, column=0)

filter_label = tk.Label(root, text="Filter:")
filter_label.grid(row=0, column=1)
filter_var = tk.StringVar()
filter_entry = tk.Entry(root, textvariable=filter_var, state='disabled')
filter_entry.grid(row=0, column=2)

# функция для включения/выключения поля ввода фильтра в зависимости от состояния флажка "Use Filter"
def toggle_filter_entry():
    if use_filter_var.get():
        filter_entry.config(state='normal')
    else:
        filter_entry.config(state='disabled')

# добавление обработчика события на изменение состояния флажка "Use Filter"
use_filter_var.trace('w', lambda name, index, mode, use_filter_var=use_filter_var: toggle_filter_entry())

# создание кнопок "Start" и "Stop"
start_button = tk.Button(root, text="Start", command=start_sniffing)
start_button.grid(row=1, column=0)

stop_button = tk.Button(root, text="Stop", command=stop_sniffing_func)
stop_button.grid(row=1, column=1)

# запуск главного цикла обработки событий
root.mainloop()