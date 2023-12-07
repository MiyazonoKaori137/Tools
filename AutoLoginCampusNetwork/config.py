import argparse
import yaml
import os
import shutil
import sys
from typing import Dict, List

class Account_Config:
    def __init__(self, user_account: int,operator: int, user_password: str):
        self.user_account = str(user_account)
        self.operator = operator
        self.user_password = user_password

    @classmethod
    def from_list(cls, data: Dict[str, any]):
        return cls(**data)

class Wifi_Config:
    def __init__(self,NetWorks: List[Dict[str, any]]):
        self.NetWorks = NetWorks

    @classmethod
    def from_list(cls, data: Dict[str, any]):
        return cls(**data)
    
class Function_Config:
    def __init__(self,AutoConnect: bool,NetworkSpeed: bool,EnsureDependencies: bool,Debug: bool):
        self.AutoConnect = AutoConnect
        self.NetworkSpeed = NetworkSpeed
        self.EnsureDependencies = EnsureDependencies
        self.Debug = Debug
    
    @classmethod
    def from_list(cls, data: Dict[str, any]):
        return cls(**data)

class Config:
    def __init__(self, config_file: str):
        if not os.path.isfile(config_file) and os.path.isfile("config-template.yaml"):
            shutil.copy(src="config-template.yaml", dst=config_file)
            print(f"已根据默认配置文件config-template.yaml生成配置文件{config_file},请按该配置文件的说明进行配置后重新运行。")
            sys.exit(0)
        with open(config_file, 'r', encoding='utf-8') as file:
            yaml_config: Dict[str, any] = yaml.safe_load(file.read())
            self.account_config: Account_Config = Account_Config.from_list(yaml_config['Account'])
            self.wifi_config: Wifi_Config = Wifi_Config.from_list(yaml_config['WiFi'])
            self.function_config: Function_Config = Function_Config.from_list(yaml_config['Function'])
            operator_index = yaml_config['Account']['operator']
            operators = ["@telecom", "@cmcc", "@unicom"]
            self.account_config.operator = operators[operator_index-1]
