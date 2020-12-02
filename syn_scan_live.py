import pyshark
import datetime
import logging
import pandas as pd
import matplotlib.pyplot as plt
import socket
import coloredlogs
from Packet_Repository import insert_packet_info
from send_mail import send_mail


date = datetime.datetime.now()

format_string = '%(levelname)s: %(asctime)s: %(message)s'
logging.basicConfig(filename="log_SYNSCAN_Live_" + str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".log",
                    level=logging.DEBUG, format=format_string)

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')
coloredlogs.install(level='DEBUG', logger=logger)
file = "./SYN_SCAN_" + \
           str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".pcap"

output = open(file, "a+")
# change interface name based on wireshark
cap = pyshark.LiveCapture(interface="en0", output_file=file)
cap.sniff(packet_count=1000)

# cap = pyshark.FileCapture('/Users/harish/Downloads/capture_2020-11-27.pcap')
# cap.load_packets(packet_count=100)

def print_logger(pkt):
    # for printing on the terminal
    logger.debug("Packet Arrival Time : %s", pkt.frame_info.time)
    logger.debug("Packet Number : %s", pkt.frame_info.number)
    logger.debug("Source IP: %s", pkt.ip.src)
    logger.debug("Destination IP: %s", pkt.ip.dst)
    logger.debug("Packet Length : %s", pkt.length)


tcp_conv = {}


def add_Value_to_tcpCov(dict, key, value):
    if key not in dict:
        dict[key] = list()
    dict[key].append(value)
    # print(dict)
    return dict



for pkt in cap:
    if "tcp" in pkt:
        if pkt.tcp.seq == '0' and pkt.tcp.ack == "0" and pkt.tcp.flags_syn == '1':
            add_Value_to_tcpCov(tcp_conv, pkt.tcp.stream, "SYN")
        if pkt.tcp.seq == "0" and pkt.tcp.ack == "1" and pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '1':
            add_Value_to_tcpCov(tcp_conv, pkt.tcp.stream, "SYN-ACK")
        if pkt.tcp.seq == "1" and pkt.tcp.flags_reset == '1':
            add_Value_to_tcpCov(tcp_conv, pkt.tcp.stream, "RST")

tcp_stream = set()
for key, list_of_values in tcp_conv.items():
    if "SYN" in list_of_values:
        if "SYN-ACK" in list_of_values:
            if "RST" in list_of_values:
                tcp_stream.add(key)

for pkt in cap:
    if "tcp" in pkt and pkt.tcp.stream in tcp_stream:
        if len(tcp_stream) > 2:
            logger.info(
                "------------------------------------------------------------------------------------------------------------------------------------------------")
            logger.critical("BAD TRAFFIC : POTENTIAL SYN SCAN ATTACK")
            print_logger(pkt)
            logger.debug("Source Port : %s", pkt.tcp.srcport)
            logger.debug("Destination Port : %s", pkt.tcp.dstport)
            insert_packet_info((int(pkt.frame_info.number) , str(pkt.frame_info.time) ,
                                str(pkt.ip.src) if 'ip' in pkt else str(pkt.ipv6.src) if 'ipv6' in pkt else 0 ,
                                int(pkt.tcp.srcport),
                                str(pkt.ip.dst) if 'ip' in pkt else str(pkt.ipv6.dst) if 'ipv6' in pkt else 0 ,
                                int(pkt.tcp.dstport),
                                int(pkt.length) , "BAD TRAFFIC : POTENTIAL SYN SCAN ATTACK"))

start_timestamp = 0.0

for pkt in cap:
    if "tcp" in pkt and pkt.tcp.stream in tcp_stream:
        start_timestamp = float(pkt.frame_info.time_epoch)
        break

end_timestamp = start_timestamp + 1
relative_timestamp = 0.0
firstPkt_timestamp = start_timestamp
incoming_traffic_plot = []
count = 0

for pkt in cap:
    if "tcp" in pkt and pkt.tcp.stream in tcp_stream:
        if start_timestamp <= float(pkt.frame_info.time_epoch) < end_timestamp:
            count += 1
        elif float(pkt.frame_info.time_epoch) > end_timestamp:
            relative_timestamp = int(end_timestamp) - int(firstPkt_timestamp)
            incoming_traffic_plot.append({'Time': relative_timestamp,
                                          'Incoming Packets': count})
            start_timestamp = end_timestamp
            end_timestamp = end_timestamp + 1
            count = 1

df = pd.DataFrame(data=incoming_traffic_plot)
df.plot(x='Time', y='Incoming Packets', color='r')
plt.show()
plt.close()

send_mail("Attack type - SYN Scanning")




