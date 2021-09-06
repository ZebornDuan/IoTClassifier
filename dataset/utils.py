from scapy.all import *
from scapy.utils import PcapReader


def get_entropy_feature(pcap_file, output_file):
    def calculate_entropy(packet_payload):
        byte_map = {}
        for byte in packet_payload:
            byte_map[byte] = byte_map.get(byte, 0) + 1
        p = {k: v / len(payload) for k, v in byte_map.items()}
        e = 0
        for p_i in p.values():
            if p_i:
                e += -p_i * math.log(p_i, 256)
        return e

    with PcapReader(pcap_file) as pcapfile:
        for index, packet in enumerate(pcapfile):
            if IP in packet:
                if TCP in packet[IP]:
                    payload = bytes(packet[IP][TCP].payload)
                    entropy = calculate_entropy(payload)
                    output_file.write('{},{}\n'.format(index, entropy))
                elif UDP in packet[IP]:
                    payload = bytes(packet[IP][UDP].payload)
                    entropy = calculate_entropy(payload)
                    output_file.write('{},{}\n'.format(index, entropy))
                else:
                    output_file.write('{},\n'.format(index))
            else:
                output_file.write('{},\n'.format(index))
    output_file.close()


def generate_feature(file, feature_list, selected_feature, alias):
    line = file.readline()
    while line:
        fields = line.split('$')
        feature_vector = tuple(
            fields[feature_list.index(alias.get(feature_name, feature_name))] for feature_name in selected_feature)
        yield feature_vector
        line = file.readline()
    file.close()
