from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.utils import hexdump

ip = IP(dst="192.168.1.12")
icmp = ICMP(type=8, code=0)
packet = ip/icmp/"Hello, world!"

# распечатать содержимое пакета в шестнадцатеричном виде
hexdump(packet)

# отправьте пакет
send(packet)
