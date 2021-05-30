import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.rtp import RTP
from scapy.packet import Raw
from threading import *
from time import time, sleep

a = 0
secret_packets = []
traffic = []


def SIP_BYE_detecting():
    global a
    while True:
        SIP = scapy.sniff(filter="(src 213.170.81.130  and dst 192.168.42.62) or (dst 213.170.81.130  and src "
                                 "192.168.42.62)", iface="eth0", count=1)
        if SIP[0][Raw].load[0] == 66 and SIP[0][Raw].load[1] == 89 and SIP[0][Raw].load[2] == 69:
            a = 1
            break
    print("finish 1: ", a)
    return


def traffic_sniff():
    global a
    global traffic
    while a == 0:
        traffic.append(scapy.sniff(filter="port 8002", iface="eth0", timeout=10))
    return


t1 = Thread(target=SIP_BYE_detecting)
t2 = Thread(target=traffic_sniff)

t2.start()
t1.start()

t1.join()
t2.join()

k = 0
n = 0

print("Message:")
packets = []
message = []
for i in traffic:
    for j in i:
        packets.append(j)

i = 0
noise_error = 0
try:
    while i in range(len(packets) - 1):
        print("0_I: ", i, "\n")
        prefix = 0
        while prefix < 229:
            i += 1
            if packets[i][IP].src == "192.168.42.62" and packets[i][IP].dst == "192.168.42.233":
                prefix += 1
        middle_block_len = packets[i][Raw].load[-1]
        middle_block_len = (middle_block_len % 100) + 149
        j = 0
        while j < middle_block_len:
            i += 1
            if packets[i][IP].src == "192.168.42.233" and packets[i][IP].dst == "192.168.42.62":
                j += 1

        error_rate = packets[i][Raw].load[2] * 256 + packets[i][Raw].load[3]
        if noise_error == 0:
            error_rate -= 100
        if noise_error == 1:
            error_rate -= 250
        while True:
            if (packets[i][IP].src == "192.168.42.233") and \
                    ((packets[i][Raw].load[2] * 256 + packets[i][Raw].load[3]) < error_rate):
                break
            i -= 1
        while True:
            i += 1
            if (packets[i][IP].src == "192.168.42.233") and (packets[i][Raw].load[1] == 136):
                break
        secret_packets_numb = packets[i][Raw].load[2] * 256 + packets[i][Raw].load[3] + 10
        fake_sequence = []
        i += 1
        while (packets[i][IP].src == "192.168.42.233" and packets[i][Raw].load[1] == 136) is False:
            if packets[i][IP].src == "192.168.42.233":
                fake_sequence.append(packets[i])
            i += 1
        fake_sequence = fake_sequence[3:]
        limit = 0
        for v in fake_sequence:
            if v[Raw].load[2] * 256 + v[Raw].load[3] == secret_packets_numb:
                message.append(v[Raw].load)
                secret_packets_numb += 7
                limit += 1
                if limit == 10:
                    break
        noise_error += 1
except:
    print(len(traffic))
    print(i)
    print(len(message))
    print("result is:")
    for u in message:
        print(u[2] * 256 + u[3])
        print(u[12:172], "\n")

