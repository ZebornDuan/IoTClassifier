import os

from dataset.utils import generate_feature


class YourthingsDataset(object):
    DEVICE_IOT_LIST = '''
        GoogleOnHub                           192.168.0.2
        SamsungSmartThingsHub                 192.168.0.4
        PhilipsHUEHub                         192.168.0.5
        InsteonHub                            192.168.0.6
        Sonos                                 192.168.0.7
        SecurifiAlmond                        192.168.0.8
        NestCamera                            192.168.0.10
        BelkinWeMoMotionSensor                192.168.0.12
        LIFXVirtualBulb                       192.168.0.13
        BelkinWeMoSwitch                      192.168.0.14
        AmazonEcho                            192.168.0.15
        WinkHub                               192.168.0.16
        BelkinNetcam                          192.168.0.18
        RingDoorbell                          192.168.0.19
        RokuTV                                192.168.0.21
        Roku4                                 192.168.0.22
        AmazonFireTV                          192.168.0.23
        nVidiaShield                          192.168.0.24
        AppleTV(4thGen)                       192.168.0.25
        BelkinWeMoLink                        192.168.0.26
        NetgearArloCamera                     192.168.0.27
        D-LinkDCS-5009LCamera                 192.168.0.28
        LogitechLogiCircle                    192.168.0.29
        Canary                                192.168.0.30
        PiperNV                               192.168.0.31
        WithingsHome                          192.168.0.32
        WeMoCrockpot                          192.168.0.33
        MiCasaVerdeVeraLite                   192.168.0.34
        ChineseWebcam                         192.168.0.35
        AugustDoorbellCam                     192.168.0.36
        TP-LinkWiFiPlug                       192.168.0.37
        ChamberlainmyQGarageOpener            192.168.0.38
        LogitechHarmonyHub                    192.168.0.39
        CasetaWirelessHub                     192.168.0.41
        GoogleHomeMini                        192.168.0.42
        GoogleHome                            192.168.0.43
        BoseSoundTouch10                      192.168.0.44
        HarmonKardonInvoke                    192.168.0.45
        AppleHomePod                          192.168.0.47
        Roomba                                192.168.0.48
        SamsungSmartTV                        192.168.0.49
        KoogeekLightbulb                      192.168.0.50
        TP-LinkSmartWiFiLEDBulb               192.168.0.51
        Wink2Hub                              192.168.0.52
        NestCamIQ                             192.168.0.53
        NestGuard                             192.168.0.54
    '''.split()

    def __init__(self):
        self.iot_list = {}
        for i in range(0, len(YourthingsDataset.DEVICE_IOT_LIST), 2):
            self.iot_list[YourthingsDataset.DEVICE_IOT_LIST[i]] = YourthingsDataset.DEVICE_IOT_LIST[i + 1]
        self.ip_device_map = {v: k for k, v in self.iot_list.items()}
        self.dates = list(range(10, 20))
        self.feature_list = ['index', 'timestamp', 'size', 'eth_type', 'ip_src', 'ip_dst', 'ip_proto', 'ip_opt_padding',
                             'ip_opt_ra', 'tcp_srcport', 'tcp_dstport', 'tcp_stream', 'tcp_window_size', 'tcp_len',
                             'ssl_ciphersuite', 'udp_srcport', 'udp_dstport', 'udp_stream', 'dns_query_name', 'http',
                             'ntp']
        self._feature_map = {'address_src': 'ip_src', 'address_dst': 'ip_dst'}

    def run_tshark(self):
        base_dir = os.getcwd()
        command = 'tshark -r {}/Yourthings/pcap-raw/{}.pcap -T fields -E separator=$ -e frame.number -e ' \
                  'frame.time_epoch -e frame.len ' \
                  '-e eth.type -e ip.src -e ip.dst -e ip.proto -e ip.opt.padding -e ip.opt.ra -e tcp.srcport -e ' \
                  'tcp.dstport -e tcp.stream -e tcp.window_size -e tcp.len -e ssl.handshake.ciphersuite -e ' \
                  'udp.srcport -e udp.dstport -e udp.stream -e dns.qry.name -e http -e ntp ' \
                  '>{}/Yourthings/features/10-{}.csv '
        for d in self.dates:
            file_name = '{:02}'.format(d)
            os.system(command.format(base_dir, file_name, base_dir, file_name))

    def data_generator(self, dates, features):
        file_path = './Yourthings/features/10-{}.csv'
        for date in dates:
            file_name = file_path.format(date)
            csv_file = open(file_name, 'r')
            yield from generate_feature(csv_file, self.feature_list, features, self._feature_map)
            print('finish reading {}'.format(file_name))

