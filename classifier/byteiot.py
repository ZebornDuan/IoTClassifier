from classifier.base import Classifier

import math
import pickle


class ByteIoTClassifier(Classifier):
    def __init__(self, k=1, interval=1800, bidirectional=True, metric='hellinger'):
        super(ByteIoTClassifier, self).__init__()
        self.k = k
        self.interval = interval
        self.bidirectional = bidirectional
        self.metric = {
            'hellinger': self.calculate_hellinger_distance,
            'total-variation': self.calculate_total_variation_distance
        }.get(metric)
        self.selected_features = ['timestamp', 'size', 'address_src', 'address_dst', 'ip_src', 'ip_dst', 'ip_proto']
        self.tag = 'byteiot'
        self._sample_set = None

    @staticmethod
    def _get_sample(counter, dataset, half_dataset):
        for addr, c in counter.items():
            if c:
                total = sum((v for v in c.values()))
                half_c = {k: v for k, v in c.items() if k[1] == 0x01}
                half_total = sum((v for v in half_c.values()))
                for k in c.keys():
                    c[k] = c[k] / total
                for k in half_c.keys():
                    half_c[k] = half_c[k] / half_total
                dataset[addr].append(c)
                if half_c:
                    half_dataset[addr].append(half_c)

    def get_dataset(self, raw_dataset, generator):
        counter = {addr: {} for addr in raw_dataset.iot_list.values()}
        dataset = {addr: [] for addr in raw_dataset.iot_list.values()}
        half_dataset = {addr: [] for addr in raw_dataset.iot_list.values()}
        instance_index = 0
        for t, size, addr_src, addr_dst, _ip_src, _ip_dst, _ip_proto in generator:
            t = int(float(t))
            size = int(size)
            if instance_index and t // self.interval != instance_index:
                self._get_sample(counter, dataset, half_dataset)
                instance_index = t // self.interval
                counter = {addr: {} for addr in raw_dataset.iot_list.values()}
            if not instance_index:
                instance_index = t // self.interval
            if addr_src in counter.keys():
                counter[addr_src][(size, 0x01)] = counter[addr_src].get((size, 0x01), 0) + 1
            if addr_dst in counter.keys():
                counter[addr_dst][(size, 0x00)] = counter[addr_dst].get((size, 0x00), 0) + 1
        self._get_sample(counter, dataset, half_dataset)
        if self.bidirectional:
            return dataset
        else:
            return half_dataset

    def train_model(self, dataset, training_set_archive):
        with open(training_set_archive, 'rb') as f:
            train_set = pickle.load(f)
            self._sample_set = train_set

    def test(self, dataset, test_set_archive=None):
        true_count, false_count = 0, 0
        with open(test_set_archive, 'rb') as f:
            test_set = pickle.load(f)
        for address, sample in test_set.items():
            for s in sample:
                d, result, nearest_neighbors = 1.0, '', []
                for train_addr, train_samples in self._sample_set.items():
                    for train_s in train_samples:
                        distance = self.metric(s, train_s)
                        if len(nearest_neighbors) < self.k:
                            nearest_neighbors.append((distance, train_addr))
                        else:
                            max_distance = max([nn[0] for nn in nearest_neighbors])
                            if distance < max_distance:
                                nearest_neighbors = [nn for nn in nearest_neighbors if nn[0] < max_distance]
                                nearest_neighbors.append((distance, train_addr))
                counter, min_distance, max_count = {}, {}, 0
                for nn in nearest_neighbors:
                    counter[nn[1]] = counter.get(nn[1], 0) + 1
                    if nn[0] < min_distance.get(nn[1], 1.0):
                        min_distance[nn[1]] = nn[0]
                for nn in nearest_neighbors:
                    if counter[nn[1]] > max_count or (counter[nn[1]] == max_count and min_distance[nn[1]] < d):
                        d, result = nn
                if result == address:
                    true_count += 1
                else:
                    false_count += 1
            print(true_count, true_count + false_count, true_count / (true_count + false_count))
        accuracy = true_count / (true_count + false_count)
        print(accuracy)
        return accuracy

    @staticmethod
    def calculate_total_variation_distance(d1, d2):
        s1 = set(d1.keys())
        s2 = set(d2.keys())
        s = s1 | s2
        d = 0.0
        for packer_header in s:
            d += abs(d1.get(packer_header, 0.0) - d2.get(packer_header, 0.0))
        d = d / 2
        return d

    @staticmethod
    def calculate_hellinger_distance(d1, d2):
        s1 = set(d1.keys())
        s2 = set(d2.keys())
        s = s1 | s2
        d = 0.0
        for packer_header in s:
            p1 = d1.get(packer_header, 0.0)
            p2 = d2.get(packer_header, 0.0)
            d += (math.sqrt(p1) - math.sqrt(p2)) ** 2
        d = math.sqrt(d) / math.sqrt(2)
        return d

