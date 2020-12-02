import socket
import coloredlogs
import logging
from Packet_Repository import insert_packet_info
import datetime
import math
import pandas as pd
import matplotlib.pyplot as plt


class PacketImpl:

    def __init__(self):
        date = datetime.datetime.now()
        self.format_string = '%(levelname)s: %(asctime)s: %(message)s'
        logging.basicConfig(filename="log_Final_LiveCapture_" + str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".log",
                    level=logging.DEBUG, format=self.format_string)
        self.logger = logging.getLogger(__name__)
        coloredlogs.install(level='DEBUG', logger=self.logger)

        self.pkt_counter_dict = {}
        self.pkt_time_slot_dict = {}
        self.first_pkt_time_dict = {}
        self.time_diff = 1

        self.threshold = 1
        self.pkt_counter_prefix = 'Incoming Packets - {}'

    # getting ipv4 address of the local host
    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    # getting ipv6 address of the local host
    def get_ipv6(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.connect(('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '::1'
        finally:
            s.close()
        return ip

    # for printing on the terminal and on log file
    def print_logger(self, pkt):
        self.logger.debug("Packet Arrival Time : %s", pkt.frame_info.time)
        self.logger.debug("Packet Number : %s", pkt.frame_info.number)
        self.logger.debug("Source IP: %s", 'ip' in pkt and pkt.ip.src or pkt.ipv6.src)
        self.logger.debug("Destination IP: %s", 'ip' in pkt and pkt.ip.dst or pkt.ipv6.dst)
        self.logger.debug("Packet Length : %s", pkt.length)

    # attack vector detection logic #1 Ping of Death
    # logging ICMP packets with size more than 64 bytes
    def check_ping_of_death(self, pkt, attack_type):
        if ('ip' in pkt and pkt.ip.dst == self.get_ip()) or ('ipv6' in pkt and pkt.ipv6.dst == self.get_ipv6()):
            if int(pkt.length) > 64:
                self.process_pkt_counter(pkt, attack_type)
                self.logger.info("----------------------------------------------------------------------------------")
                self.logger.critical("BAD TRAFFIC : POTENTIAL ICMP PING OF DEATH ATTACK")
                self.print_logger(pkt)
                insert_packet_info((int(pkt.frame_info.number), str(pkt.frame_info.time),
                                    str(pkt.ip.src) if 'ip' in pkt else str(pkt.ipv6.src) if 'ipv6' in pkt else 0, 0,
                                    str(pkt.ip.dst) if 'ip' in pkt else str(pkt.ipv6.dst) if 'ipv6' in pkt else 0, 0,
                                    int(pkt.length), "BAD TRAFFIC : POTENTIAL ICMP PING OF DEATH ATTACK"))

    # attack vector detection logic #2 ICMP Flood`
    #------------------------------------------------------------------------ logging ICMP packets with size more than 64 bytes
    def check_icmp_flood(self, pkt, attack_type):
        pkt_counter_key = self.get_pkt_counter_key(attack_type)
        if ('ip' in pkt and pkt.ip.dst == self.get_ip()) or ('ipv6' in pkt and pkt.ipv6.dst == self.get_ipv6()):
            prev_time_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            self.process_pkt_counter(pkt, attack_type)
            current_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            if (prev_time_slot != current_slot) and \
                    self.pkt_counter_dict[attack_type][prev_time_slot][pkt_counter_key] <= self.threshold:
                self.pkt_counter_dict[attack_type][prev_time_slot][pkt_counter_key] = 0
            if self.pkt_counter_dict[attack_type][current_slot][pkt_counter_key] > self.threshold:
                self.logger.info(
                    "--------------------------------------------------------------------------------------------------------------------")
                self.logger.critical("BAD TRAFFIC : POTENTIAL ICMP FLOODING ATTACK")
                self.print_logger(pkt)
                insert_packet_info((int(pkt.frame_info.number) , str(pkt.frame_info.time) ,
                                    str(pkt.ip.src) if 'ip' in pkt else str(pkt.ipv6.src) if 'ipv6' in pkt else 0 , 0 ,
                                    str(pkt.ip.dst) if 'ip' in pkt else str(pkt.ipv6.dst) if 'ipv6' in pkt else 0 , 0 ,
                                    int(pkt.length) ,
                                    "BAD TRAFFIC : POTENTIAL ICMP FLOODING ATTACK"))


    # attack vector detection logic #3 SYN Flood`
    # ------------------------------------------------------------------------logging SYN packets with size more than 64 bytes
    def check_syn_flood(self, pkt, attack_type):
        pkt_counter_key = self.get_pkt_counter_key(attack_type)
        if (('ip' in pkt and pkt.ip.dst == self.get_ip()) or ('ipv6' in pkt and pkt.ipv6.dst == self.get_ipv6())) and \
                pkt.tcp.seq == '0' and pkt.tcp.flags_syn == '1':
            prev_time_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            self.process_pkt_counter(pkt , attack_type)
            current_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            if (prev_time_slot != current_slot) and \
                    self.pkt_counter_dict[attack_type][prev_time_slot][pkt_counter_key]<= 0:
                self.pkt_counter_dict[attack_type][prev_time_slot][pkt_counter_key] = 0
            if self.pkt_counter_dict[attack_type][current_slot][pkt_counter_key] > 0:
                self.logger.info("--------------------------------------------------------------------------------------------------------------------")
                self.logger.critical("BAD TRAFFIC : POTENTIAL SYN FLOODING ATTACK")
                self.print_logger(pkt)
                self.logger.debug("Source Port : %s" , pkt.tcp.srcport)
                self.logger.debug("Destination Port : %s" , pkt.tcp.dstport)
                insert_packet_info((int(pkt.frame_info.number) , str(pkt.frame_info.time) ,
                                    str(pkt.ip.src) if 'ip' in pkt else str(pkt.ipv6.src) if 'ipv6' in pkt else 0 ,
                                    int(pkt.tcp.srcport) ,
                                    str(pkt.ip.dst) if 'ip' in pkt else str(pkt.ipv6.dst) if 'ipv6' in pkt else 0 ,
                                    int(pkt.tcp.dstport) ,
                                    int(pkt.length) , "BAD TRAFFIC : POTENTIAL SYN FLOODING ATTACK"))

    # attack vector detection logic #4 UPD Flood`
    # ------------------------------------------------------------------------logging UDP packets with size more than 64 bytes
    def check_udp_flood(self, pkt, attack_type):
        pkt_counter_key = self.get_pkt_counter_key(attack_type)
        if (('ip' in pkt and pkt.ip.dst == self.get_ip()) or (
                'ipv6' in pkt and pkt.ipv6.dst == self.get_ipv6())):
            prev_time_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            self.process_pkt_counter(pkt, attack_type)
            current_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            if (prev_time_slot != current_slot) and \
                    self.pkt_counter_dict[attack_type][prev_time_slot][
                        pkt_counter_key] <= 30:
                self.pkt_counter_dict[attack_type][prev_time_slot][pkt_counter_key] = 0
            if self.pkt_counter_dict[attack_type][current_slot][pkt_counter_key] > 30:
                self.logger.info(
                    "--------------------------------------------------------------------------------------------------------------------")
                self.logger.critical("BAD TRAFFIC : POTENTIAL UDP FLOODING ATTACK")
                self.print_logger(pkt)
                insert_packet_info((int(pkt.frame_info.number) , str(pkt.frame_info.time) ,
                                    str(pkt.ip.src) if 'ip' in pkt else str(pkt.ipv6.src) if 'ipv6' in pkt else 0 ,
                                    int(pkt.udp.srcport) ,
                                    str(pkt.ip.dst) if 'ip' in pkt else str(pkt.ipv6.dst) if 'ipv6' in pkt else 0 ,
                                    int(pkt.udp.dstport) ,
                                    int(pkt.length) , "BAD TRAFFIC : POTENTIAL UDP Flooding ATTACK"))






    def process_pkt_counter(self, pkt, attack_type):
        if self.pkt_time_slot_dict[attack_type][0] <= math.floor(float(pkt.frame_info.time_epoch))\
                < self.pkt_time_slot_dict[attack_type][1]:
            current_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            self.add_data_pkt_counter(attack_type, current_slot, 1)
        else:
            self.pkt_time_slot_dict[attack_type] = (self.pkt_time_slot_dict[attack_type][1],
                                                    self.pkt_time_slot_dict[attack_type][1] + self.time_diff)
            current_slot = self.pkt_time_slot_dict[attack_type][1] - self.first_pkt_time_dict[attack_type]
            # The below logic is to add time slot even if there is no packet
            self.add_data_pkt_counter(attack_type, current_slot, 0)
            self.process_pkt_counter(pkt, attack_type)

    def add_pkt_time_slot(self, pkt, attack_type):
        start_timestamp = math.floor(float(pkt.frame_info.time_epoch))
        self.first_pkt_time_dict[attack_type] = start_timestamp
        self.pkt_time_slot_dict[attack_type] = (start_timestamp, start_timestamp + self.time_diff)

    def add_data_pkt_counter(self, attack_type, time_slot_num, count):
        pkt_counter_key = self.get_pkt_counter_key(attack_type)
        if attack_type not in self.pkt_counter_dict:
            self.pkt_counter_dict[attack_type] = {}
        if time_slot_num not in self.pkt_counter_dict[attack_type]:
            self.pkt_counter_dict[attack_type][time_slot_num] = {'Time': time_slot_num, pkt_counter_key: 0}
        current_count = self.pkt_counter_dict[attack_type][time_slot_num][pkt_counter_key]
        self.pkt_counter_dict[attack_type][time_slot_num][pkt_counter_key] = current_count + count

    def show_on_plot(self, attack_type):
        df = pd.DataFrame(data=self.pkt_counter_dict[attack_type].values())
        df.plot(x='Time', y=self.get_pkt_counter_key(attack_type), color='r')
        plt.show()
        plt.close()

    def get_pkt_counter_key(self, attack_type):
        return self.pkt_counter_prefix.format(attack_type.value)