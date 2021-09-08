from dataset.utils import get_entropy_feature, generate_feature

import os


class PrivateDataset(object):
    DEVICE_IOT_LIST = '''
        YeeLinkLight              50:ec:50:7a:b3:d0
        MijiaCamera               5c:e5:0c:a9:71:fa
        MiDoorbell2L              d4:d2:d6:4e:9f:d5
        ChuangMiPlug              44:23:7c:57:c9:94
        DMakerFan                 64:90:c1:b5:76:bb
        DreamerHumidifier         64:90:c1:db:a9:f3
        MIAISoundBox              ec:fa:5c:0a:f8:a3
        ZHIMI-AirPurifier         5c:e5:0c:ba:c4:ff
        HuaweiSmartPlug           cc:50:e3:dc:f8:d7
        TP-LinkCamera             80:ea:07:aa:40:3b
        HuaweiSmartCamera         48:46:c1:51:b6:46
        WizLight                  a8:bb:50:22:d2:55
        BloodPressureMeasure      d0:49:00:47:5e:90
        AISpeakerMini             48:3f:e9:8d:4d:e5
        DataFrame                 00:e0:4c:8e:c9:52
        TuyaSmartPlug             c4:4f:33:99:ab:a2
        AquraGateway              54:ef:44:cb:1e:38
    '''.split()

    # WaterLoggingSensor
    # BodySensor
    # Temperature&HumiditySensor
    # SmokeAlarm
    # VibrationSensor
    # Door&WindowSensor
    # CubeController

    def __init__(self):
        self.iot_list = {}
        for i in range(0, len(PrivateDataset.DEVICE_IOT_LIST), 2):
            self.iot_list[PrivateDataset.DEVICE_IOT_LIST[i]] = PrivateDataset.DEVICE_IOT_LIST[i + 1]
        self.mac_device_map = {v: k for k, v in self.iot_list.items()}
        self._feature_map = {'address_src': 'eth_src', 'address_dst': 'eth_dst'}
        self.month = [11] * 13 + [12] * 31
        self.date = [17, 18] + list(range(20, 31)) + list(range(1, 32))
        self.default_training_range = {
            'train': {'month': self.month[:22], 'date': self.date[:22]},
            'test': {'month': self.month[22:], 'date': self.date[22:]}
        }
        self.feature_list = ['index', 'timestamp', 'size', 'eth_src', 'eth_dst',
                             'eth_type', 'ip_src', 'ip_dst', 'ip_proto', 'ip_opt_padding',
                             'ip_opt_ra', 'tcp_srcport', 'tcp_dstport', 'tcp_stream', 'tcp_window_size', 'tcp_len',
                             'ssl_ciphersuite', 'udp_srcport', 'udp_dstport', 'udp_stream', 'dns_query_name', 'http',
                             'ntp']

    def run_tshark(self):
        base_dir = os.getcwd()
        command = 'tshark -r {}/silent-test/pcap/{}.pcap -T fields -E separator=$ -e frame.number -e frame.time_epoch '\
                  '-e frame.len -e eth.src -e eth.dst ' \
                  '-e eth.type -e ip.src -e ip.dst -e ip.proto -e ip.opt.padding -e ip.opt.ra -e tcp.srcport -e ' \
                  'tcp.dstport -e tcp.stream -e tcp.window_size -e tcp.len -e ssl.handshake.ciphersuite -e ' \
                  'udp.srcport -e udp.dstport -e udp.stream -e dns.qry.name -e http -e ntp >{}/silent-test/csv/{}.csv'
        for m, d in zip(self.month, self.date):
            file_name = '2020{:02d}{:02d}'.format(m, d)
            print(command.format(base_dir, file_name, base_dir, file_name))
            os.system(command.format(base_dir, file_name, base_dir, file_name))

    def get_entropy_feature(self):
        for m, d in zip(self.month, self.date):
            file_name = '2020{:02d}{:02d}'.format(m, d)
            pcap_file = './silent_test/pcap/{}.pcap'.format(file_name)
            output_file = open('./silent_test/entropy/{}.csv'.format(file_name), 'w')
            get_entropy_feature(pcap_file, output_file)

    def data_generator(self, month, date, features):
        if len(month) != len(date):
            raise ValueError("invalid parameter: len(month) != len(date)")
        for m, d in zip(month, date):
            feature_path = './silent_test/csv/2020{:02d}{:02d}.csv'.format(m, d)
            f = open(feature_path, 'r')
            yield from generate_feature(f, self.feature_list, features, self._feature_map)
            print('finish reading {}-{}'.format(m, d))


if __name__ == '__main__':
    private_dataset = PrivateDataset()
    private_dataset.run_tshark()
    private_dataset.get_entropy_feature()
