import math
import os

from dataset.utils import get_entropy_feature, generate_feature


class UNSWDataset(object):
    DEVICE_IOT_LIST = '''
        SmartThings                     d0:52:a8:00:67:5e
        AmazonEcho                      44:65:0d:56:cc:d3
        NetatmoWelcome                  70:ee:50:18:34:43
        TP-LinkDayNightCloudCamera      f4:f2:6d:93:51:f1
        SamsungSmartCam                 00:16:6c:ab:6b:88
        Dropcam                         30:8c:fb:2f:e4:b2
        InsteonCamera                   00:62:6e:51:27:2e
        Unknown                         e8:ab:fa:19:de:4f
        WithingsSmartBabyMonitor        00:24:e4:11:18:a8
        BelkinWemoSwitch                ec:1a:59:79:f4:89
        TP-LinkSmartPlug                50:c7:bf:00:56:39
        iHome                           74:c6:3b:29:d7:1d
        BelkinWemoMotionSensor          ec:1a:59:83:28:11
        NESTProtectSmokeAlarm           18:b4:30:25:be:e4
        NetatmoWeatherStation           70:ee:50:03:b8:ac
        WithingsSmartScale              00:24:e4:1b:6f:96
        BlipcareBloodPressureMeter      74:6a:89:00:2e:25
        WithingsAuraSmartSleepSensor    00:24:e4:20:28:c6
        LightBulbsLiFXSmartBulb         d0:73:d5:01:83:08
        TribySpeaker                    18:b7:9e:02:20:44
        PIX-STARPhoto-frame             e0:76:d0:33:bb:85
        HPPrinter                       70:5a:0f:e4:9b:c0
    '''.split()

    DEVICE_NONIOT_LIST = '''
        SamsungGalaxyTab                08:21:ef:3b:fc:e3
        AndroidPhone                    40:f3:08:ff:1e:da
        Laptop                          74:2f:68:81:69:42
        MacBook                         ac:bc:32:d4:6f:2f
        AndroidPhone                    b4:ce:f6:a7:a3:c2
        IPhone                          d0:a6:37:df:a1:e1
        MacBook/Iphone                  f4:5c:89:93:cc:85
    '''.split()

    # TPLinkRouterBridgeLAN(Gateway)  14:cc:20:51:33:ea
    # NestDropcam                     30:8c:fb:b6:ea:45

    def __init__(self):
        self.device_list, self.iot_list, self.non_iot_list = {}, {}, {}
        for i in range(0, len(UNSWDataset.DEVICE_IOT_LIST), 2):
            self.iot_list[UNSWDataset.DEVICE_IOT_LIST[i]] = UNSWDataset.DEVICE_IOT_LIST[i + 1]
            self.device_list[UNSWDataset.DEVICE_IOT_LIST[i]] = UNSWDataset.DEVICE_IOT_LIST[i + 1]
        for i in range(0, len(UNSWDataset.DEVICE_NONIOT_LIST), 2):
            self.non_iot_list[UNSWDataset.DEVICE_NONIOT_LIST[i]] = \
                UNSWDataset.DEVICE_NONIOT_LIST[i + 1]
            self.device_list[UNSWDataset.DEVICE_NONIOT_LIST[i]] = \
                UNSWDataset.DEVICE_NONIOT_LIST[i + 1]
        self.mac_device_map = {v: k for k, v in self.iot_list.items()}
        self.mac_device_map['non-iot'] = 'non-iot'
        self.label_map = {mac: i for i, mac in enumerate(self.mac_device_map.keys())}
        self.month = [9] * 8 + [10] * 12
        self.date = list(range(23, 31)) + list(range(1, 13))
        self.feature_list = ['index', 'timestamp', 'eth_type', 'ip_src', 'ip_dst', 'ip_proto', 'ip_opt_padding',
                             'ip_opt_ra', 'tcp_srcport', 'tcp_dstport', 'tcp_stream', 'tcp_window_size', 'tcp_len',
                             'ssl_ciphersuite', 'udp_srcport', 'udp_dstport', 'udp_stream', 'dns_query_name', 'http',
                             'ntp']

    def run_tshark(self):
        command = 'tshark -r ./UNSWData/pcap-raw/{}.pcap -T fields -E separator=$ -e frame.number -e frame.time_epoch '\
                  '-e eth.type -e ip.src -e ip.dst -e ip.proto -e ip.opt.padding -e ip.opt.ra -e tcp.srcport -e ' \
                  'tcp.dstport -e tcp.stream -e tcp.window_size -e tcp.len -e ssl.handshake.ciphersuite -e ' \
                  'udp.srcport -e udp.dstport -e udp.stream -e dns.qry.name -e http -e ntp >./UNSWData/features/{}.csv'
        for m, d in zip(self.month, self.date):
            file_name = '16-{:02d}-{:02d}'.format(m, d)
            os.system(command.format(file_name, file_name))

    def get_entropy_feature(self):
        for m, d in zip(self.month, self.date):
            file_name = '16-{:02d}-{:02d}'.format(m, d)
            pcap_file = './pcap-raw/{}.pcap'.format(file_name)
            output_file = open('./entropy/{}.csv'.format(file_name), 'w')
            get_entropy_feature(pcap_file, output_file)

    def data_generator(self, month, date, features):
        if len(month) != len(date):
            raise ValueError("invalid parameter: len(month) != len(date)")
        for m, d in zip(month, date):
            feature_path = './UNSWData/features/16-{:02d}-{:02d}.csv'.format(m, d)
            f = open(feature_path, 'r')
            yield from generate_feature(f, self.feature_list, features)
            print('finish reading {}-{}'.format(m, d))


if __name__ == '__main__':
    unsw_dataset = UNSWDataset()
    unsw_dataset.run_tshark()
    unsw_dataset.get_entropy_feature()
