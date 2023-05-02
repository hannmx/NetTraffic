import tkinter as tk
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *
import datetime
import tkinter.messagebox as messagebox

# создание GUI
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("300x300")

# функция для обработки события нажатия кнопки "Start"
def start_sniffing():
    global stop_sniffing, sniffer, use_filter_var, filter_var, packet_count_after_id, last_update_after_id
    stop_sniffing = False
    label.config(text="Анализирую пакеты...")
    use_filter = use_filter_var.get()
    if use_filter:
        # задать фильтр для сниффера
        filter_str = filter_var.get()
        sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet, filter=filter_str)
    else:
        sniffer = AsyncSniffer(iface='Беспроводная сеть', prn=handle_packet)
    
    sniffer.start()

    # инициализировать идентификаторы вызовов функций через 1 секунду
    packet_count_after_id = root.after(1000, update_packet_count)
    last_update_after_id = root.after(1000, update_last_update_time)

# функция для обработки события нажатия кнопки "Stop"
def stop_sniffing_func():
    global stop_sniffing, sniffer, packet_count_after_id, last_update_after_id
    stop_sniffing = True
    if 'sniffer' in globals():
        label.config(text="Остановка трафика...")
        sniffer.stop()
    # остановить вызов функций через 1 секунду
    root.after_cancel(packet_count_after_id)
    root.after_cancel(last_update_after_id)

# функция для завершения программы
def exit_program():
    root.destroy()

# переменная для хранения количества пакетов
packet_count = 0

# функция для обновления метки с количеством пакетов
def update_packet_count():
    if not stop_sniffing:
        global packet_count
        packet_count += 1
        packet_count_label.config(text=f"Пакетов: {packet_count}")
        # вызвать функцию через 1 секунду
        root.after(1000, update_packet_count)

# функция для обновления метки с временем последнего обновления
def update_last_update_time():
    if not stop_sniffing:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_update_label.config(text=f"Последнее обновление: {current_time}")
        # вызвать функцию через 1 секунду
        root.after(1000, update_last_update_time)

# список ключевых слов для поиска в пакетах
keywords = ["hack", "virus", "malware", "spyware"]

# функция, которая будет вызываться для каждого перехваченного пакета
def handle_packet(packet):
    global packet_count, stop_sniffing
    # вызываем функцию для обновления количества пакетов
    update_packet_count()
    # вызываем функцию для обновления времени последнего обновления
    update_last_update_time()
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

            # проверить, содержит ли пакет небезопасный трафик
            unsafe_traffic = False
            for keyword in keywords:
                if keyword in str(packet):
                    unsafe_traffic = True
                    break
            
            # если пакет содержит небезопасный трафик, выведем предупреждение
            if unsafe_traffic:
                messagebox.showwarning("Unsafe Traffic Detected", "!!! WARNING: Unsafe traffic detected !!!")

            # вывести информацию о пакете
            packet_info = f'Source IP: {s_addr} Destination IP: {d_addr} ' \
                          f'Source Port: {source_port} Destination Port: {dest_port} ' \
                          f'Sequence: {sequence} Acknowledgement: {acknowledgement} ' \
                          f'TCP header length: {tcph_length}'
            print(packet_info)

            # записать информацию о пакете в файл
            with open("sniffer_output.txt", "a") as f:
                f.write(f"{packet_info}\n")
        elif protocol == 17:
            # извлечь заголовок UDP
            udph = packet[UDP]
            source_port = udph.sport
            dest_port = udph.dport
            length = udph.len

            # проверить, содержит ли пакет небезопасный трафик
            unsafe_traffic = False
            for keyword in keywords:
                if keyword in str(packet):
                    unsafe_traffic = True
                    break
            
            # если пакет содержит небезопасный трафик, выведем предупреждение
            if unsafe_traffic:
                messagebox.showwarning("Unsafe Traffic Detected", "!!! WARNING: Unsafe traffic detected !!!")

            # вывести информацию о пакете
            packet_info = f'Source IP: {s_addr} Destination IP: {d_addr} ' \
                          f'Source Port: {source_port} Destination Port: {dest_port} ' \
                          f'Length: {length} UDP header length: 8'
            print(packet_info)

            # записать информацию о пакете в файл
            with open("sniffer_output.txt", "a") as f:
                f.write(f"{packet_info}\n")
        # если это ICMP-пакет
        elif protocol == 1:
            # извлечь заголовок ICMP
            icmph = packet[ICMP]
            type = icmph.type
            code = icmph.code
            packet_length = len(packet)

            # проверить, содержит ли пакет небезопасный трафик
            unsafe_traffic = False
            for keyword in keywords:
                if keyword in str(packet):
                    unsafe_traffic = True
                    break

            # если пакет содержит небезопасный трафик, выведем предупреждение
            if unsafe_traffic:
                messagebox.showwarning("Unsafe Traffic Detected", "!!! WARNING: Unsafe traffic detected !!!")
            # вывести информацию о пакете
            packet_info = f'Source IP: {s_addr} Destination IP: {d_addr} ' \
                          f'ICMP type: {type} ICMP code: {code} ' \
                          f'ICMP packet length: {packet_length}'
            print(packet_info)

            # записать информацию о пакете в файл
            with open("sniffer_output.txt", "a") as f:
                f.write(f"{packet_info}\n")

# создаем метку для вывода сообщения
label = tk.Label(root, text="Анализирую пакеты...")
label.pack()

# создаем метку для вывода сообщения в root1
packet_count_label = tk.Label(root, text="Пакетов: 0")
packet_count_label.pack()

# создаем метку для вывода времени последнего обновления
last_update_label = tk.Label(root, text="")
last_update_label.pack()

# создание метки и поля ввода для фильтра
use_filter_var = tk.BooleanVar()
use_filter_var.set(False)
use_filter_checkbutton = tk.Checkbutton(root, text="Use Filter", variable=use_filter_var)
use_filter_checkbutton.pack()

filter_label = tk.Label(root, text="Filter:")
filter_label.pack()
filter_var = tk.StringVar()
filter_entry = tk.Entry(root, textvariable=filter_var, state='disabled')
filter_entry.pack()

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
start_button.pack()

stop_button = tk.Button(root, text="Stop", command=stop_sniffing_func)
stop_button.pack()

# создание кнопки "Exit"
exit_button = tk.Button(root, text="Exit", command=exit_program)
exit_button.pack()

# запуск главного цикла обработки событий
root.mainloop()