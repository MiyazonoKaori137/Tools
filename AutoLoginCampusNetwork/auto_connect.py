import re
import socket
import time
import urllib.parse
from config import Config
import uuid
import random
from multiprocessing import Process
from pip._internal import main as pipmain
import sys
import subprocess

all_config = Config("config.yaml")

if all_config.function_config.EnsureDependencies:
    try:
        import pywifi
        from pywifi import const
        from loguru import logger
        import requests
        from ping3 import ping
        import psutil

    except ImportError:
        pipmain(["install", "-r", "requirements.txt", "-i", "https://pypi.tuna.tsinghua.edu.cn/simple",
                    "--trusted-host", "pypi.tuna.tsinghua.edu.cn"])
        print("依赖安装完成")
        import pywifi
        from pywifi import const
        from loguru import logger
        import requests
        from ping3 import ping
        import psutil
    
import pywifi
from pywifi import const
from loguru import logger
import requests
from ping3 import ping
import psutil

class AutoLogin():
    def __init__(self,user_account,operator,user_password):
        self.user_account = urllib.parse.quote(user_account)
        self.operator = urllib.parse.quote(operator)
        self.user_password = urllib.parse.quote(user_password)

        self.mac_address = '-'.join([uuid.UUID(int=uuid.getnode()).hex[-12:].upper()[i:i+2] for i in range(0, 11, 2)])
        self.fake_mac_address = '-'.join([''.join(random.choices([hex(i)[-1].upper() for i in range(16)], k=12)[i:i+2]) for i in range(0, 11, 2)])
        self.v = random.randint(3000,9999) # 不清楚这个url中的v参数是什么。如果能用代码获取到，就可以不用重启程序就能认证成功
        
        self.wifi = pywifi.PyWiFi()

    def get_wifi_name(self,):
        try:
            cmd = "netsh wlan show interfaces"
            result = subprocess.run(cmd.split(), stdout=subprocess.PIPE)
            return re.search(r'SSID\s+:\s(.+)', result.stdout.decode('gbk')).group(1).strip()
        except:
            logger.error("获取接口失败")
    
    def statu(self,):
        success_count = 0
        for i in range(5):
            try:
                q = requests.get("http://www.baidu.com", timeout=500)
                m = re.search(r'STATUS OK', q.text)
                if m:
                    success_count += 1
            except:
                pass
        if success_count >= 3:
            if all_config.function_config.Debug:
                logger.success("网络连接成功")
            return 0
        else:
            logger.error("网络连接失败")
            return 1

    def login(self,):
        try:
            self.s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self.s.connect(("8.8.8.8",80))
            self.ip = self.s.getsockname()[0]
            self.url_first = f"http://10.17.8.18:801/eportal/portal/login?callback=dr1003&login_method=1&user_account={self.user_account}{self.operator}&user_password={self.user_password}&wlan_user_ip={self.ip}&wlan_user_ipv6=&wlan_user_mac={self.mac_address}&wlan_ac_ip=10.17.4.1&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v=3965&lang=zh"
            response = requests.get(self.url_first)
            logger.info(response.text)
            if response.text.find("认证成功") != -1:
                logger.success("登录成功")
                return True
            elif response.text.find("认证失败") != -1:
                logger.error("登录失败")
                return False
        except Exception as e:
            logger.error(f"登录失败:{e}")
            return False
        
    def connect_wifi(self,which_wifi):
        try:
            ifaces = self.wifi.interfaces()[0]
            profile = pywifi.Profile()
            profile.ssid = which_wifi['ssid']
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = None if which_wifi['password'] == 'None' else which_wifi['password']
            tmp_profile = ifaces.add_network_profile(profile)
            ifaces.connect(tmp_profile)
            time.sleep(2)
            if ifaces.status() == const.IFACE_CONNECTED:
                return True
            else:
                return False
        except Exception as e:
            logger.error(f"WiFi连接异常: {e}")
            return False
        
    def check_wifi_connected(self,):
        ifaces = self.wifi.interfaces()[0]
        if ifaces.status() == const.IFACE_CONNECTED:
            return True
        else:
            return False

    def get_wifi_signal_strength(self,):
        wifi_networks = {}
        ifaces = self.wifi.interfaces()[0]
        ifaces.scan()
        time.sleep(1)
        for i in range(5):
            scan_results = ifaces.scan_results()
            for network in scan_results:
                ssid = network.ssid.encode('latin1').decode('utf-8')
                signal_strength = network.signal
                if ssid not in wifi_networks:
                    wifi_networks[ssid] = [signal_strength]
                else:
                    wifi_networks[ssid].append(signal_strength)
            time.sleep(0.2)
        for key in wifi_networks:
            wifi_networks[key] = sum(wifi_networks[key]) / len(wifi_networks[key])

        wifi_networks = sorted(wifi_networks.items(), key=lambda x:x[1], reverse=True)
        config_exit_wifi = all_config.wifi_config.NetWorks
        for network_info in config_exit_wifi.values():
            network_info['signal_strength'] = -1000
            for wifi in wifi_networks:
                ssid, signal_strength = wifi
                if network_info['ssid'] == ssid:
                    network_info['signal_strength'] = signal_strength
                    break
        
        config_exit_wifi = sorted(config_exit_wifi.items(), key=lambda x:x[1]['signal_strength'], reverse=True)
        return config_exit_wifi
    
    # 测量当前WiFi速度和延迟，没啥用，speedtest-cli测速又响应太慢了
    def measure_wifi_speed(self,interval=2):
        ping_value = ping("www.baidu.com")
        speed_sent = 0
        speed_recv = 0
        if all_config.function_config.NetworkSpeed:
            net_io1 = psutil.net_io_counters()
            time.sleep(interval)
            net_io2 = psutil.net_io_counters()
            bytes_sent = net_io2.bytes_sent - net_io1.bytes_sent
            bytes_recv = net_io2.bytes_recv - net_io1.bytes_recv
            speed_sent = bytes_sent / interval / 1024 / 1024
            speed_recv = bytes_recv / interval / 1024 / 1024
        return speed_sent, speed_recv, ping_value

    def process_wifi(self,):
        while True:
            time.sleep(2)
            if all_config.function_config.NetworkSpeed:
                speed_sent, speed_recv, ping_value = self.measure_wifi_speed()
                logger.info(f"当前WiFi上传速度: {speed_sent}MB/s, 当前WiFi下载速度:{speed_recv}MB/s, 延迟: {ping_value}ms")

            if not self.check_wifi_connected():
                logger.error("WiFi未连接")
                if not self.connect_wifi(self.get_wifi_signal_strength()[0][1]):
                    logger.error("WiFi连接失败")
                    continue
            else:
                if all_config.function_config.Debug:
                    logger.success("WiFi已连接")
                    print(self.get_wifi_signal_strength()[0][1])
                    
                if self.get_wifi_name() == self.get_wifi_signal_strength()[0][1]['ssid']:
                    if all_config.function_config.Debug:
                        logger.success("当前WiFi是信号最强的WiFi")
                else:
                    logger.info("当前WiFi不是信号最强的WiFi,正在连接信号最强的WiFi")
                    if not self.connect_wifi(self.get_wifi_signal_strength()[0][1]):
                        logger.error("WiFi连接失败")
                        continue
                    else:
                        if all_config.function_config.Debug:
                            logger.success("WiFi连接成功")

    def process_login(self,):
        while True:
            time.sleep(2)
            if self.get_wifi_name() == all_config.wifi_config.NetWorks['Network 1']['ssid']:
                if self.statu():
                    if not self.login():
                        # 退出这个进程，然后重启这个进程
                        sys.exit(1)

    def run_two_process(self,):
        logger.success("--------正在监测网络连接状态-------")
        logger.warning("出现 pywifi ******* ERROR Open handle failed!为正常现象，不影响使用")
        p1 = Process(target=self.process_wifi)
        p1.start()
        
        while True:
            p2 = Process(target=self.process_login)
            p2.start()
            p2.join()
            if not p2.is_alive():
                logger.error("登录失败,正在重启这个进程")
                p2 = Process(target=self.process_login)
                p2.start()

    def run_one_process(self,):
        logger.success("--------正在监测网络连接状态--------")
        logger.warning("出现 pywifi ****** ERROR Open handle failed!为正常现象，不影响使用")
        while True:
            time.sleep(2)
            if all_config.function_config.NetworkSpeed:
                speed_sent, speed_recv, ping_value = self.measure_wifi_speed()
                logger.info(f"当前WiFi上传速度: {speed_sent}MB/s, 当前WiFi下载速度:{speed_recv}MB/s, 延迟: {ping_value}ms")

            if not self.check_wifi_connected():
                logger.error("WiFi未连接")
                if not self.connect_wifi(self.get_wifi_signal_strength()[0][1]):
                    logger.error("WiFi连接失败")
                    continue
            else:
                if all_config.function_config.Debug:
                    logger.success("WiFi已连接")
                    print(self.get_wifi_signal_strength()[0][1])
                if self.get_wifi_name() == self.get_wifi_signal_strength()[0][1]['ssid']:
                    if all_config.function_config.Debug:
                        logger.success("当前WiFi是信号最强的WiFi")
                else:
                    logger.info("当前WiFi不是信号最强的WiFi")
                    if not self.connect_wifi(self.get_wifi_signal_strength()[0][1]):
                        logger.error("WiFi连接失败")
                        continue
                    else:
                        if all_config.function_config.Debug:
                            logger.success("WiFi连接成功")
        
            if self.get_wifi_name() == all_config.wifi_config.NetWorks['Network 1']['ssid']:
                if self.statu():
                    if not self.login():
                        # 自动退出程序，然后重启程序，以便认证成功
                        logger.error("登录失败,正在重启程序,以便认证成功!")
                        time.sleep(1)
                        sys.exit(1)

if __name__ == "__main__":
    Auto  = AutoLogin(all_config.account_config.user_account, all_config.account_config.operator, all_config.account_config.user_password)
    Auto.run_one_process()
    # 然而使用子进程的方式并没有解决认证失败的问题，不知道为什么，只好采用单进程+bat脚本的方式来重启程序
    # Auto.run_two_process()