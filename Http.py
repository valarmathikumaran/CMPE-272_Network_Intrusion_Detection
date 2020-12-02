import pyshark
from http_impl import PacketImpl
import enum
from send_mail import send_mail
import sys
import datetime

class ATTACK_TYPE(enum.Enum):
    HTTP_Payload_Injection = 'Http_payload_injection'

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

            if 'http' in protocols:
                self.packet_impl.check_http_payload_injection(pkt , ATTACK_TYPE.HTTP_Payload_Injection)


        for attack_type in ATTACK_TYPE:
            send_mail(attack_type)
            self.packet_impl.show_on_plot(attack_type)


if __name__ == '__main__':
    date = datetime.datetime.now()
    cap = pyshark.FileCapture('./http_payload.pcap' , keep_packets=False)

    processPacket = ProcessPacket()
    processPacket.process_packet()



