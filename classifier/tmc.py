from classifier.base import Classifier

from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
import numpy as np


class TMCClassifier(Classifier):
    '''
    Sivanathan, Arunan, et al. "Classifying IoT devices in smart environments
    using network traffic characteristics." IEEE Transactions on Mobile 
    Computing 18.8 (2018): 1745-1759.
    '''
    
    def __init__(self, interval=1800):
        super(TMCClassifier, self).__init__()
        self.interval = interval
        self.tag = 'TMC'
        self.selected_features = ['timestamp', 'size', 'address_src', 'address_dst', 'tcp_dstport', 'ssl_ciphersuite',
                                  'udp_dstport', 'dns_query_name', 'ntp']
        self._mnb1, self._mnb2, self._mnb3 = None, None, None
        self._reverse_c, self._reverse_r, self._reverse_d = None, None, None

    @staticmethod
    def _get_sample(counter, dataset):
        for addr, c in counter.items():
            if c['v']:
                feature = {
                    'dns': c['dns'],
                    'rp': c['rp'],
                    'cs': c['cs'],
                    'flow_volume': c['v'],
                    'flow_duration': c['last-packet'] - c['first-packet'],
                    'sleep_time': c['t']
                }
                if feature['flow_duration']:
                    feature['flow_radio'] = feature['flow_volume'] / feature['flow_duration']
                else:
                    feature['flow_radio'] = 0
                if len(c['dt']) == 0:
                    feature['dns_interval'] = -1
                elif len(c['dt']) == 1:
                    feature['dns_interval'] = 0
                else:
                    s = 0
                    for i in range(1, len(c['dt'])):
                        s += c['dt'][i] - c['dt'][i - 1]
                    feature['dns_interval'] = s / (len(c['dt']) - 1)
                if len(c['nt']) == 0:
                    feature['ntp_interval'] = -1
                elif len(c['nt']) == 1:
                    feature['ntp_interval'] = 0
                else:
                    s = 0
                    for i in range(1, len(c['nt'])):
                        s += c['nt'][i] - c['nt'][i - 1]
                    feature['ntp_interval'] = s / (len(c['nt']) - 1)
                dataset[addr].append(feature)

    def get_dataset(self, raw_dataset, generator):
        def _get_feature(v, address, packet_time, packet_size):
            if 'first-packet' not in v[address]:
                v[address]['first-packet'] = packet_time
            if v[address]['last-packet'] and packet_time - v[address]['last-packet'] > v[address]['t']:
                v[address]['t'] = packet_time - v[address]['last-packet']
            v[address]['last-packet'] = packet_time
            v[address]['v'] += packet_size

        counter = {
            address: {'dns': [], 'rp': [], 'cs': [], 'v': 0, 't': 0, 'dt': [], 'nt': [], 'last-packet': 0}
            for address in raw_dataset.device_list.values()
        }
        dataset = {address: [] for address in raw_dataset.device_list.values()}
        instance_index = 0
        for t, size, addr_src, addr_dst, tcp_dstport, ciphersuite, udp_dstport, dns, ntp in generator:
            t, size = float(t), int(size)
            if instance_index and t // self.interval != instance_index:
                self._get_sample(counter, dataset)
                instance_index = t // self.interval
                counter = {
                    address: {'dns': [], 'rp': [], 'cs': [], 'v': 0, 't': 0, 'dt': [], 'nt': [], 'last-packet': 0}
                    for address in raw_dataset.device_list.values()
                }
            if not instance_index:
                instance_index = t // self.interval
            if addr_src in counter.keys():
                _get_feature(counter, addr_src, t, size)
                if dns:
                    for dns_i in dns.split(','):
                        counter[addr_src]['dns'].append(dns_i)
                    counter[addr_src]['dt'].append(t)
                if ntp:
                    counter[addr_src]['nt'].append(t)
                if ciphersuite:
                    cipher_suite = ciphersuite.split(',')
                    for cs in cipher_suite:
                        for cs_i in cs.split(';'):
                            counter[addr_src]['cs'].append(int(cs_i))
                if tcp_dstport:
                    counter[addr_src]['rp'].append(int(tcp_dstport))
                if udp_dstport:
                    counter[addr_src]['rp'].append(int(udp_dstport))
            if addr_dst in counter.keys():
                _get_feature(counter, addr_dst, t, size)
        self._get_sample(counter, dataset)
        bidirectional_non_iot = []
        for mac in raw_dataset.non_iot_list.values():
            bidirectional_non_iot.extend(dataset[mac])
            dataset.pop(mac)
        dataset['non-iot'] = bidirectional_non_iot
        if not self._mnb1:
            self._train_preprocessor(dataset, raw_dataset)
        return self._get_final_dataset(dataset, raw_dataset)

    def _get_frequency_features(self, raw_feature):
        x_dns, x_rp, x_cs = [0] * len(self._reverse_d), [0] * len(self._reverse_r), [0] * len(self._reverse_c)
        for domain_name in raw_feature['dns']:
            if domain_name in self._reverse_d:
                x_dns[self._reverse_d[domain_name]] += 1
        for port in raw_feature['rp']:
            if port in self._reverse_r:
                x_rp[self._reverse_r[port]] += 1
        for cipher_suite in raw_feature['cs']:
            if cipher_suite in self._reverse_c:
                x_cs[self._reverse_c[cipher_suite]] += 1
        return x_dns, x_rp, x_cs

    def _train_preprocessor(self, train_set, dataset):
        dns_dictionary = set()
        rp_dictionary = set()
        cs_dictionary = set()
        for addr, features in train_set.items():
            for feature in features:
                for dns in feature['dns']:
                    dns_dictionary.add(dns)
                for rp in feature['rp']:
                    rp_dictionary.add(rp)
                for cs in feature['cs']:
                    cs_dictionary.add(cs)
        d_d = {i: v for i, v in enumerate(dns_dictionary)}
        r_d = {i: v for i, v in enumerate(rp_dictionary)}
        c_d = {i: v for i, v in enumerate(cs_dictionary)}
        self._reverse_d = {v: k for k, v in d_d.items()}
        self._reverse_r = {v: k for k, v in r_d.items()}
        self._reverse_c = {v: k for k, v in c_d.items()}
        x_d, x_r, x_c, y_d, y_r, y_c = [], [], [], [], [], []

        for addr, features in train_set.items():
            for feature in features:
                x_d_i, x_r_i, x_c_i = self._get_frequency_features(feature)
                x_d.append(x_d_i)
                x_c.append(x_c_i)
                x_r.append(x_r_i)
                y_d.append(dataset.label_map[addr])
                y_r.append(dataset.label_map[addr])
                y_c.append(dataset.label_map[addr])
        x_d, x_r, x_c = np.array(x_d), np.array(x_r), np.array(x_c)
        y_d, y_c, y_r = np.array(y_d), np.array(y_c), np.array(y_r)
        mnb1, mnb2, mnb3 = MultinomialNB(), MultinomialNB(), MultinomialNB()
        mnb1.fit(x_d, y_d)
        mnb2.fit(x_r, y_r)
        if x_c:
            mnb3.fit(x_c, y_c)
        else:
            mnb3 = None
        self._mnb1, self._mnb2, self._mnb3 = mnb1, mnb2, mnb3

    def _get_final_dataset(self, original_dataset, raw_dataset):
        final_features = {addr: [] for addr in raw_dataset.addr_device_map.keys()}
        for addr, features in original_dataset.items():
            for feature in features:
                feature_vector = [feature['flow_volume'], feature['flow_duration'], feature['flow_radio'],
                                  feature['sleep_time'], feature['dns_interval'], feature['ntp_interval']]
                x_d_i, x_r_i, x_c_i = self._get_frequency_features(feature)
                y_d_i = self._mnb1.predict(np.array([x_d_i]))
                y_d_i_p = self._mnb1.predict_proba(np.array([x_d_i]))
                y_r_i = self._mnb2.predict(np.array([x_r_i]))
                y_r_i_p = self._mnb2.predict_proba(np.array([x_r_i]))

                feature_vector.append(y_d_i[0])
                feature_vector.extend(list(y_d_i_p[0]))
                feature_vector.append(y_r_i[0])
                feature_vector.extend(list(y_r_i_p[0]))

                if self._mnb3:
                    y_c_i = self._mnb3.predict(np.array([x_c_i]))
                    y_c_i_p = self._mnb3.predict_proba(np.array([x_c_i]))
                    feature_vector.append(y_c_i[0])
                    feature_vector.extend(list(y_c_i_p[0]))
                final_features[addr].append(feature_vector)
        return final_features

    def train_model(self, dataset, training_set_archive):
        x_train, y_train = self.get_training_dataset(dataset, training_set_archive)
        rf = RandomForestClassifier(n_estimators=100)
        rf.fit(x_train, y_train)
        self.model = rf

