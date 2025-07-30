import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
import logging
import logging.handlers
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import base64
import psutil
from cachetools import TTLCache
import threading

# 配置日志系统
def setup_logging(config):
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 你的简化版 main 函数
def main():
    logging.warning("开始测试 IPTV 处理脚本")
    url_states = load_url_states_local()
    
    # 测试数据
    test_channels = [
        ("CCTV1", "http://example.com/cctv1.m3u8"),
        ("湖南卫视", "http://example.com/hunan.m3u8"),
        ("购物频道", "http://example.com/shopping.m3u8")
    ]
    
    # 测试过滤
    filtered_channels = filter_and_modify_channels(test_channels)
    logging.warning(f"过滤后频道: {filtered_channels}")
    
    # 测试分类
    categorized, uncategorized = categorize_channels(filtered_channels)
    logging.warning(f"分类结果: {categorized}")
    logging.warning(f"未分类: {uncategorized}")
    
    # 保存分类结果
    process_and_save_channels_by_category(filtered_channels, url_states, {})
    
    # 合并文件
    merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states)
    
    save_url_states_local(url_states)
    logging.warning("测试完成")

if __name__ == "__main__":
    main()
