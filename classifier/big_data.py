from classifier.base import Classifier

from sklearn.ensemble import RandomForestClassifier


class BigDataClassifier(Classifier):
    def __init__(self, interval=1800, n=10):
        '''
        Shahid, Mustafizur R., et al. "IoT devices recognition through network traffic 
        analysis." 2018 IEEE international conference on big data (big data). IEEE, 2018.
        '''
        super(BigDataClassifier, self).__init__()
        self.interval = interval
        self.n = n
        self.tag = 'big-data'
        self.selected_features = ['timestamp', 'size', 'address_src', 'address_dst', 'tcp_stream']

    @staticmethod
    def _get_sample(stream_packet, dataset, n, n1, n2):
        for address, stream in stream_packet.items():
            features = []
            for _, s_series in stream.items():
                feature = []
                if len(s_series['s-out']) < n:
                    feature.extend(s_series['s-out'])
                    feature.extend([0] * (n - len(s_series['s-out'])))
                    for t_i in range(1, len(s_series['t-out'])):
                        feature.append(s_series['t-out'][t_i] - s_series['t-out'][t_i - 1])
                    feature.extend([0] * (n1 - len(feature)))
                else:
                    feature.extend(s_series['s-out'][:n])
                    for t_i in range(1, n):
                        feature.append(s_series['t-out'][t_i] - s_series['t-out'][t_i - 1])
                if len(s_series['s-in']) < n:
                    feature.extend(s_series['s-in'])
                    feature.extend([0] * (n - len(s_series['s-in'])))
                    for t_i in range(1, len(s_series['t-in'])):
                        feature.append(s_series['t-in'][t_i] - s_series['t-in'][t_i - 1])
                    feature.extend([0] * (n2 - len(feature)))
                else:
                    feature.extend(s_series['s-in'][:n])
                    for t_i in range(1, n):
                        feature.append(s_series['t-in'][t_i] - s_series['t-in'][t_i - 1])
                if feature:
                    features.append(feature)
            if features:
                dataset[address].extend(features)

    def get_dataset(self, raw_dataset, generator):
        instance_index = 0
        n1, n2 = 2*self.n - 1, 4*self.n - 2
        dataset = {address: [] for address in raw_dataset.iot_list.values()}
        stream_packet = {address: {} for address in raw_dataset.iot_list.values()}
        for t, size, address_src, address_dst, tcp_stream in generator:
            t, size = float(t), int(size)
            if instance_index and int(t) // self.interval != instance_index:
                self._get_sample(stream_packet, dataset, self.n, n1, n2)
                instance_index = int(t) // self.interval
                stream_packet = {address: {} for address in raw_dataset.iot_list.values()}
            if not instance_index:
                instance_index = int(t) // self.interval
            if tcp_stream:
                if address_src in raw_dataset.iot_list.values():
                    if not stream_packet[address_src].get(int(tcp_stream), None):
                        stream_packet[address_src][int(tcp_stream)] = {'s-in': [], 's-out': [], 't-in': [], 't-out': []}
                    stream_packet[address_src][int(tcp_stream)]['s-out'].append(size)
                    stream_packet[address_src][int(tcp_stream)]['t-out'].append(t)
                if address_dst in raw_dataset.iot_list.values():
                    if not stream_packet[address_dst].get(int(tcp_stream), None):
                        stream_packet[address_dst][int(tcp_stream)] = {'s-in': [], 's-out': [], 't-in': [], 't-out': []}
                    stream_packet[address_dst][int(tcp_stream)]['s-in'].append(size)
                    stream_packet[address_dst][int(tcp_stream)]['t-in'].append(t)
        self._get_sample(stream_packet, dataset, self.n, n1, n2)
        return dataset

    def train_model(self, dataset, training_set_archive):
        x_train, y_train = self.get_training_dataset(dataset, training_set_archive)
        rf = RandomForestClassifier(n_estimators=100)
        rf.fit(x_train, y_train)
        self.model = rf

