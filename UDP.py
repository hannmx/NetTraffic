from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.utils import hexdump

# установите значение поля dst равным IP-адресу вашего компьютера
ip = IP(dst="192.168.1.12")
udp = UDP(dport=1234)
packet = ip/udp/"Hello, world!"

# распечатать содержимое пакета в шестнадцатеричном виде
hexdump(packet)

# отправьте пакет
send(packet)