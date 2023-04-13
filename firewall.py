import re

# Define inbound and outbound rules
inbound_rules = [
    {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
     {"src_ip": "140.113.17.5",  "dst_ip": "192.168.18.219"},
    {"src_ip": "192.168.1.3",  "dst_ip": "192.168.1.2",}
]

outbound_rules = [
    {"src_ip": "192.168.1.2",  "dst_ip": "192.168.1.1"},
    {"src_ip": "140.113.17.5", "dst_ip": "192.168.18.219"},
    {"src_ip": "192.168.1.2", "dst_ip": "192.168.1.3"}
]

# Define function to check if a packet matches a rule
def packet_matches_rule(packet, rule):
    if (packet["src_ip"] == rule["src_ip"] and
       
        packet["dst_ip"] == rule["dst_ip"] ):
        return True
    else:
        return False

# Read packets from tcp.txt and udp.txt files
tcp_packets = []
udp_packets = []

with open("tcp.txt", "r") as f:
    tcp_packets = f.readlines()

with open("udp.txt", "r") as f:
    udp_packets = f.readlines()

# Filter packets based on inbound and outbound rules
filtered_packets = []
#    m = re.match(r"(.+):(\d+) -> (.+):(\d+)", packet)
for packet in tcp_packets + udp_packets:
    packet = packet.strip()

    #m= re.match(r"Src:\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)\s*,\s*Dst:\s+(\b(?:\d{1,3}\.){3}\d{1,3}\b)",packet)
    pattern = r'Src:\s+(\b(?:\d{0,9}\.){3}\d{0,9}\b)\s*,\s*Dst:\s+(\b(?:\d{0,9}\.){3}\d{0,9}\b)'
    matches = re.search(pattern, packet)

    if matches:
        src_ip = matches.group(1)
        dst_ip = matches.group(2)
   
   # if m:
    #    src_ip = m.group(1)
     #   src_port = m.group(2)
      #  dst_ip = m.group(3)
       # dst_port = m.group(4)

        # Check if packet matches an inbound rule
        for rule in inbound_rules:
            if packet_matches_rule({"src_ip": src_ip,  "dst_ip": dst_ip}, rule):
                filtered_packets.append(packet)
                break

        # Check if packet matches an outbound rule
        for rule in outbound_rules:
            if packet_matches_rule({"src_ip": src_ip, "dst_ip": dst_ip}, rule):
                filtered_packets.append(packet)
                break
        break
# Print filtered packets
print("Filtered packets:")
for packet in filtered_packets:
    print(packet)
 