from classifier.base import Classifier

import pickle

from sklearn.ensemble import GradientBoostingClassifier
import numpy as np

IP = 0
ICMP = 1
ICMPv6 = 2
EAPoL = 3
TCP = 4
UDP = 5
HTTP = 6
HTTPS = 7
DHCP = 8
BOOTP = 9
SSDP = 10
DNS = 11
MDNS = 12
NTP = 13
IP_OPTION_PADDING = 14
IP_OPTION_RA = 15
ENTROPY = 16
TCP_WINDOW_SIZE = 17
TCP_PAYLOAD_LENGTH = 18


class IoTSenseClassifier(Classifier):
    def __init__(self, interval, entropy_feature_archive):
        super(IoTSenseClassifier, self).__init__()
        self.tag = 'iot-sense'
        self.interval = interval
        self._entropy_feature_archive = entropy_feature_archive
        self.selected_features = ['timestamp', 'size', 'address_src', 'address_dst', 'ip_proto', 'ip_opt_padding',
                                  'ip_opt_ra', 'tcp_srcport', 'tcp_dstport', 'tcp_window_size', 'tcp_len',
                                  'udp_srcport', 'udp_dstport', 'http', 'ntp'
                                  ]

    @staticmethod
    def _get_sample(packet_series, dataset):
        for addr, packet_vectors in packet_series.items():
            interval_vector = []
            for i in range(0, len(packet_vectors), 5):
                feature_vector = []
                if i + 5 < len(packet_vectors):
                    for j in range(i, i + 5):
                        feature_vector.extend(packet_vectors[j])
                    interval_vector.append(feature_vector)
            if interval_vector:
                dataset[addr].append(interval_vector)

    def get_dataset(self, raw_dataset, generator):
        instance_index = 0
        dataset = {addr: [] for addr in raw_dataset.iot_list.values()}
        packet_series = {addr: [] for addr in raw_dataset.iot_list.values()}
        entropy_feature = open(self._entropy_feature_archive, 'r')
        for t, addr_src, addr_dst, ip_proto, eth_type, ip_option_padding, ip_option_ra, tcp_srcport, tcp_dstport, \
                tcp_window_size, tcp_len, udp_srcport, udp_dstport, http, ntp in generator:
            t = int(float(t))
            entropy = entropy_feature.readline().split(',')[-1].strip()
            entropy = float(entropy) if entropy else 0
            if instance_index and t // self.interval != instance_index:
                self._get_sample(packet_series, dataset)
                instance_index = t // self.interval
                packet_series = {mac: [] for mac in raw_dataset.iot_list.values()}
            if not instance_index:
                instance_index = t // self.interval
            packet_vector = [0] * 19
            if eth_type == '0x00008e88':
                packet_vector[EAPoL] = 1
            elif eth_type == '0x00000800' or eth_type == '0x000086dd':
                packet_vector[IP] = 1
                packet_vector[ENTROPY] = entropy
                if ip_option_padding:
                    packet_vector[IP_OPTION_PADDING] = 1
                if ip_option_ra:
                    packet_vector[IP_OPTION_RA] = 1
                if ip_proto == '6':
                    packet_vector[TCP] = 1
                    packet_vector[TCP_WINDOW_SIZE] = int(tcp_window_size) if tcp_window_size else 0
                    packet_vector[TCP_PAYLOAD_LENGTH] = int(tcp_len) if tcp_len else 0
                    if http:
                        packet_vector[HTTP] = 1
                    if tcp_srcport == '443' or tcp_dstport == '443':
                        packet_vector[HTTPS] = 1
                elif ip_proto == '17':
                    packet_vector[UDP] = 1
                    if ntp:
                        packet_vector[NTP] = 1
                    elif udp_srcport == '53' or udp_dstport == '53':
                        packet_vector[DNS] = 1
                    elif udp_srcport == '5353' or udp_dstport == '5353':
                        packet_vector[MDNS] = 1
                    elif udp_srcport in ['67', '68'] or udp_dstport in ['67', '68']:
                        packet_vector[DHCP] = 1
                        packet_vector[BOOTP] = 1
                    elif udp_srcport == '1900' or udp_dstport == '1900':
                        packet_vector[SSDP] = 1
                elif ip_proto == '1':
                    packet_vector[ICMP] = 1
            else:
                continue
            if addr_src in raw_dataset.iot_list.values():
                packet_series[addr_src].append(packet_vector)
            if addr_dst in raw_dataset.iot_list.values():
                packet_series[addr_dst].append(packet_vector)
        self._get_sample(packet_series, dataset)
        return dataset

    def train_model(self, dataset, training_set_archive):
        with open(training_set_archive, 'rb') as f:
            train_set = pickle.load(f)
        models = {addr: None for addr in dataset.iot_list.values()}
        for addr in dataset.iot_list.values():
            x, y = [], []
            for sample_addr, features in train_set.items():
                for feature in features:
                    x.append(feature)
                    if sample_addr == addr:
                        y.append(1)
                    else:
                        y.append(2)
            x_train, y_train = np.array(x), np.array(y)
            gbdt = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1)
            gbdt.fit(x_train, y_train)
            models[addr] = gbdt
        final_models = {k: v for k, v in models.items() if v}
        self.model = final_models

    def test(self, dataset, test_set_archive=None):
        with open(test_set_archive, 'rb') as f:
            test_set = pickle.load(f)
        true_count, false_count = 0, 0
        for addr, features in test_set.items():
            for feature in features:
                y_counter = {}
                for F in feature:
                    x_test = np.array([F])
                    result, p = '', 0.0
                    for test_addr, model in self.model.items():
                        y_predict = model.predict_proba(x_test)
                        if y_predict[0][0] > y_predict[0][1] and y_predict[0][0] > p:
                            p = y_predict[0][0]
                            result = test_addr
                    if result:
                        y_counter[result] = y_counter.get(result, 0) + 1
                result, max_count = -1, 0
                for k, v in y_counter.items():
                    if v > max_count:
                        max_count = v
                        result = k
                if result == addr:
                    true_count += 1
                else:
                    false_count += 1
            print(true_count, true_count + false_count, true_count / (true_count + false_count))
        accuracy = true_count / (true_count + false_count)
        print(accuracy)
        return accuracy
