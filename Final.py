import pyshark
from packet_impl import PacketImpl
import enum
from send_mail import send_mail
import sys
import datetime


class ATTACK_TYPE(enum.Enum):
    ICMP_PingOfDeath = 'PingOfDeath'
    ICMP_Flood = 'ICMPFlood'
    SYN_Flood = 'SYNFlood'
    UDP_Flood = 'UDPFlood'


class ProcessPacket:

    def __init__(self):
        self.packet_impl = PacketImpl()

    def process_packet(self):
        for pkt in cap:
            if pkt.frame_info.number == '1':
                for attack_type in ATTACK_TYPE:
                    self.packet_impl.add_pkt_time_slot(pkt, attack_type)
                    self.packet_impl.add_data_pkt_counter(attack_type, 1, 0)

            protocols = pkt.frame_info.protocols

            if "icmp" in protocols:
                self.packet_impl.check_ping_of_death(pkt, ATTACK_TYPE.ICMP_PingOfDeath)
                self.packet_impl.check_icmp_flood(pkt, ATTACK_TYPE.ICMP_Flood)
            if "tcp" in protocols:
                self.packet_impl.check_syn_flood(pkt , ATTACK_TYPE.SYN_Flood)
            if 'udp' in protocols:
                self.packet_impl.check_udp_flood(pkt, ATTACK_TYPE.UDP_Flood)

        for attack_type in ATTACK_TYPE:
            send_mail(attack_type)
            self.packet_impl.show_on_plot(attack_type)

if __name__ == '__main__':
    date = datetime.datetime.now()

    file = "./Final_Run_" + \
           str(date.year) + "-" + str(date.month) + "-" + str(date.day) + ".pcap"
    output = open(file , "a+")

    cap = pyshark.LiveCapture(interface="en0" , output_file=file)
    cap.sniff(packet_count=3000)

    # cap = pyshark.FileCapture('/Users/harish/Downloads/mycapture.pcapng' , keep_packets=False)

    processPacket = ProcessPacket()
    processPacket.process_packet()

    output.close()
    sys.exit(0)