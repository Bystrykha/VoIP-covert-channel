import os
import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.rtp import RTP
from scapy.packet import Raw
import random
import time
from threading import *

noise = []
secret_packets = []
fp_index = 0
id_dif = [1, 2, 3, 4]


def secret_packet_constructor(transformed_information: str):
    transformed_information += "///end///"
    if len(transformed_information) % 1600 != 0:
        difference = len(transformed_information) % 1600
        while True:
            if difference > 160:
                transformed_information += rand_bytes_create(160)
                difference -= 160
            if difference <= 160:
                transformed_information += rand_bytes_create(difference)
                break

    payload = []
    payload_begin = 0
    payload_end = 160
    while True:
        if payload_end > len(transformed_information):
            if len(transformed_information) < 160:
                payload_end = len(transformed_information)
                payload = transformed_information[payload_begin:payload_end]
                pak = Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                     dport=8002) / RTP(
                    payload_type=8) / payload
                secret_packets.append(pak)
                break
            else:
                payload_begin = payload_end
                payload_end = len(transformed_information)
                payload = transformed_information[payload_begin:payload_end]
                pak = Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                     dport=8002) / RTP(
                    payload_type=8) / payload
                secret_packets.append(pak)
                break
        else:
            payload = transformed_information[payload_begin:payload_end]
            pak = Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                 dport=8002) / RTP(
                payload_type=8) / payload
            secret_packets.append(pak)
            payload_begin = payload_end
            payload_end += 160
    for i in secret_packets:
        i[Raw].load = i[Raw].load[0:160]


def noise_create_3():
    random.seed()
    random_bytes = []
    noise_bock_number = int((len(secret_packets) + 9) / 10)
    for i in range(noise_bock_number):
        noise_block = []
        special_payload = []

        for j in range(9760):
            random_bytes.append(int(random.uniform(0, 255)))

        for j in range(4320):
            random.seed()
            a = int(random.randint(0, 1))
            if a == 0:
                b = int(random.randint(0, 1))
                if b == 0:
                    special_payload.append(chr(85))
                if b == 1:
                    c = int(random.randint(0, 1))
                    if c == 0:
                        special_payload.append(chr(84))
                    if c == 1:
                        special_payload.append(chr(87))
            if a == 1:
                special_payload.append(chr(229))
        special_payload_str = "".join(special_payload)

        begin_payload_block = 0
        end_payload_block = 160
        begin_special_payload_block = 0
        end_special_payload_block = 160

        for j in range(4):
            noise_block.append(Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                              dport=8002) / RTP(
                payload_type=8, numsync=0) / special_payload_str[
                                             begin_special_payload_block:end_special_payload_block])
            begin_special_payload_block += 160
            end_special_payload_block += 160

        noise_block[0][RTP].marker = 1

        while begin_payload_block < 9760:
            payload_int = random_bytes[begin_payload_block:end_payload_block]
            payload_chr = []
            for t in range(len(payload_int)):
                payload_chr.append(chr(payload_int[t]))
            payload_str = "".join(payload_chr)
            noise_block.append(Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                              dport=8002) / RTP(
                payload_type=8, numsync=0) / payload_str)
            begin_payload_block += 160
            end_payload_block += 160

        while begin_special_payload_block < 4320:
            noise_block.append(Ether(dst="08:00:27:a7:2a:3c") / IP(dst="192.168.42.62") / UDP(sport=8000,
                                                                                              dport=8002) / RTP(
                payload_type=8, numsync=0) / special_payload_str[
                                             begin_special_payload_block:end_special_payload_block])
            begin_special_payload_block += 160
            end_special_payload_block += 160

        noise.append(noise_block)
        for t in noise_block:
            t[RTP].load = t[RTP].load[0:160]


def traffic_sniff_2():
    sent_secret_packets = 0
    noise_packet = 0
    while sent_secret_packets < len(secret_packets):
        prefix = scapy.sniff(filter="src 192.168.42.62 and dst 192.168.42.233 and port 8000", iface="eth0", count=229)

        middle_block_len = prefix[-1][Raw].load[-1]
        middle_block_len = (middle_block_len % 100) + 149

        scapy.sniff(filter="src 192.168.42.233 and dst 192.168.42.62 and port 8000", iface="eth0",
                    count=middle_block_len)
        os.system("./bash_test")
        middle_block = scapy.sniff(filter="src 192.168.42.233 and dst 192.168.42.62 and port 8000", iface="eth0",
                                   timeout=1.4)

        last_pak_load = middle_block[-1].load
        id = middle_block[-1][IP].id
        sequence = last_pak_load[2] * 256 + last_pak_load[3]
        timestamp = ((last_pak_load[4] * 256 + last_pak_load[5]) * 256 + last_pak_load[6]) * 256 + last_pak_load[7]
        sourcesync = ((last_pak_load[8] * 256 + last_pak_load[9]) * 256 + last_pak_load[10]) * 256 + last_pak_load[11]
        try:
            block = noise[sent_secret_packets % 10]
            for k in range(4):
                sequence += 1
                timestamp += 160
                id += id_dif[int(random.uniform(0, 3))]
                block[k][IP].id = id
                block[k][RTP].sequence = sequence
                block[k][RTP].timestamp = timestamp
                block[k][RTP].sourcesync = sourcesync
                # block[k][RTP].sync = sync
                scapy.sendp(block[k])

            last_noise_packet = 4
            for k in range(10):
                for q in range(6):
                    sequence += 1
                    timestamp += 160
                    id += id_dif[int(random.uniform(0, 3))]
                    block[k][IP].id = id
                    block[last_noise_packet][RTP].sequence = sequence
                    block[last_noise_packet][RTP].timestamp = timestamp
                    block[last_noise_packet][RTP].sourcesync = sourcesync
                    scapy.sendp(block[last_noise_packet])
                    last_noise_packet += 1
                sequence += 1
                timestamp += 160
                id += id_dif[int(random.uniform(0, 3))]
                block[k][IP].id = id
                secret_packets[sent_secret_packets][RTP].sequence = sequence
                secret_packets[sent_secret_packets][RTP].timestamp = timestamp
                secret_packets[sent_secret_packets][RTP].sourcesync = sourcesync
                scapy.sendp(secret_packets[sent_secret_packets])
                sent_secret_packets += 1

            for k in range(23):
                sequence += 1
                timestamp += 160
                id += id_dif[int(random.uniform(0, 3))]
                block[k][IP].id = id
                block[last_noise_packet][RTP].sequence = sequence
                block[last_noise_packet][RTP].timestamp = timestamp
                block[last_noise_packet][RTP].sourcesync = sourcesync
                scapy.sendp(block[last_noise_packet])
            t1.start()
        except:
            os.system("./bash_test")
            time.sleep(3)
            os.system("./bash_test_2")
            break
    return


def rand_bytes_create(length: int):
    random_chars = []
    for i in range(length):
        byte = int(random.uniform(0, 255))
        random_chars.append(chr(byte))

    random_string = "".join(random_chars)
    return random_string


def silence_period():
    time.sleep(2.69)
    os.system("./bash_test")
    return


t1 = Thread(target=silence_period)
with open('text', 'r') as file:
    text = file.read()
    secret_packet_constructor(text)
    noise_create_3()
    print("fake packets are ready")
    traffic_sniff_2()

