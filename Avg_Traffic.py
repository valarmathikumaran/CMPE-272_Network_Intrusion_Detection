import pyshark
import socket
import logging
import coloredlogs


format_string = '%(levelname)s: %(asctime)s: %(message)s'
logging.basicConfig(filename="log_FileCapture_Packet.log", level=logging.DEBUG, format=format_string)

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')
coloredlogs.install(level='DEBUG', logger=logger)


cap = pyshark.LiveCapture(interface="en0")

# getting local ip address
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
local_ip = get_ip()

#counting no.of packets received in 1 second for calculating avg traffic
for pkt in cap:
    try:
        if pkt.ip.dst == local_ip:
            if float(pkt.frame_info.time_epoch) >= start_timestamp and float(pkt.frame_info.time_epoch) < end_timestamp:
                count += 1
            elif float(pkt.frame_info.time_epoch) > end_timestamp:
                logger.info("Timestamp :{} - Packet Count : {}",end_timestamp,count)
                start_timestamp = end_timestamp
                end_timestamp = end_timestamp + 1
                count = 1
    except AttributeError as e:
        pass

cap.sniff()
