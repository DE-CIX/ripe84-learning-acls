# v1.0 - convert json to juniper firewall
import json

def single(s):
    if "~" in str(s):
        return 0
    else:
        return 1

f = open("rules.json", 'r')
data = json.load(f)
data.keys()
for key in data.keys():
    protocol = data[key]['protocol']
    s_port = data[key]['port_src']
    d_port = data[key]['port_dst']
    size = data[key]['packet_size']
    # match protocol:
    if single(protocol):
        if (protocol != '*'):
            print(f"set firewall family inet filter fw-ddos term {key} from protocol {protocol}")
    else:
        protocols = eval(protocol.replace('~', ''))
        for proto in protocols:
            print(f"set firewall family inet filter fw-ddos term {key} from protocol {proto}")
    # match source port
    if single(s_port):
        if (s_port!='*'):
            print(f"set firewall family inet filter fw-ddos term {key} from source-port {s_port}")
    else:
        s_ports = eval(s_port.replace('~', ''))
        for sp in s_ports:
            print(f"set firewall family inet filter fw-ddos term {key} from source-port {sp}")
    # match destination port
    if single(d_port):
        if (d_port!='*'):
            print(f"set firewall family inet filter fw-ddos term {key} from destination-port {d_port}")
    else:
        d_ports = eval(d_port.replace('~', ''))
        for dp in d_ports:
            print(f"set firewall family inet filter fw-ddos term {key} from destination-port {dp}")

    print(f"set firewall family inet filter fw-ddos term {key} then count {key}")
    print(f"set firewall family inet filter fw-ddos term {key} then discard")

print(f"set firewall family inet filter fw-ddos term match-any then accept")
