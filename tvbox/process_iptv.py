import re
import os
import json
import logging
import requests
import time
import hashlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import List, Tuple, Dict
from retrying import retry

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tvbox/process_iptv.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class IPTVProcessor:
    def __init__(self, input_file: str, config_file: str, output_dir: str):
        self.input_file = input_file
        self.config_file = config_file
        self.output_dir = output_dir
        self.config = self.load_config()
        self.success_links = self.load_links('success_links.json')
        self.failed_links = self.load_links('failed_links.json')
        self.start_time = time.time()

    def load_config(self) -> Dict:
        """加载并校验配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            required_fields = ['categories', 'exclude_keywords', 'validate_urls', 'output_formats']
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"配置文件缺少必要字段: {field}")
            if not isinstance(config['categories'], dict):
                raise ValueError("categories 必须是字典")
            if not isinstance(config['exclude_keywords'], list):
                raise ValueError("exclude_keywords 必须是列表")
            return config
        except Exception as e:
            logging.error(f"加载配置文件 {self.config_file} 失败: {e}")
            return {
                "categories": {},
                "exclude_keywords": [],
                "validate_urls": True,
                "output_formats": ["txt", "m3u"],
                "max_threads": 10,
                "timeout": 5,
                "max_retries": 2,
                "clear_failed_links_days": 30
            }

    def load_links(self, filename: str) -> Dict:
        """加载成功或失败链接记录"""
        file_path = os.path.join(self.output_dir, filename)
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"加载 {filename} 失败: {e}")
        return {}

    def save_links(self, links: Dict, filename: str):
        """保存成功或失败链接记录"""
        file_path = os.path.join(self.output_dir, filename)
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(links, f, ensure_ascii=False, indent=2)
            logging.info(f"保存 {filename} 成功")
        except Exception as e:
            logging.error(f"保存 {filename} 失败: {e}")

    def clear_old_failed_links(self):
        """清理超过指定天数的失败链接记录"""
        clear_days = self.config.get('clear_failed_links_days', 30)
        if not clear_days:
            return
        current_time = time.time()
        updated_failed_links = {}
        for url_hash, data in self.failed_links.items():
            timestamp = data.get('timestamp', 0)
            if (current_time - timestamp) / 86400 < clear_days:
                updated_failed_links[url_hash] = data
        self.failed_links = updated_failed_links
        self.save_links(self.failed_links, 'failed_links.json')

    def get_url_hash(self, url: str) -> str:
        """生成 URL 的 MD5 哈希"""
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def is_valid_url(self, url: str) -> bool:
        """检查 URL 是否有效，支持重试"""
        try:
            response = requests.head(
                url,
                timeout=self.config.get('timeout', 5),
                allow_redirects=True
            )
            return response.status_code < 400
        except requests.RequestException:
            logging.warning(f"URL 不可访问: {url}")
            return False

    def validate_urls(self, entries: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """使用多线程验证 URL"""
        max_threads = self.config.get('max_threads', 10)
        valid_entries = []
        to_validate = []

        for name, url in entries:
            url_hash = self.get_url_hash(url)
            if url_hash in self.failed_links:
                logging.info(f"跳过已知失败链接: {url}")
                continue
            if url_hash in self.success_links:
                valid_entries.append((name, url))
                logging.info(f"使用已知成功链接: {url}")
                continue
            to_validate.append((name, url, url_hash))

        if to_validate:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_entry = {
                    executor.submit(self.is_valid_url, url): (name, url, url_hash)
                    for name, url, url_hash in to_validate
                }
                for future in as_completed(future_to_entry):
                    name, url, url_hash = future_to_entry[future]
                    try:
                        if future.result():
                            valid_entries.append((name, url))
                            self.success_links[url_hash] = {
                                'name': name,
                                'url': url,
                                'timestamp': time.time()
                            }
                            logging.info(f"验证成功: {url}")
                        else:
                            self.failed_links[url_hash] = {
                                'name': name,
                                'url': url,
                                'timestamp': time.time()
                            }
                            logging.info(f"验证失败，记录: {url}")
                    except Exception as e:
                        self.failed_links[url_hash] = {
                            'name': name,
                            'url': url,
                            'timestamp': time.time()
                        }
                        logging.warning(f"验证 URL {url} 失败: {e}")

        return valid_entries

    def categorize_entry(self, name: str) -> str:
        """根据名称分类条目"""
        for category, pattern in self.config['categories'].items():
            if re.search(pattern, name, re.IGNORECASE):
                return category
        return '其他'

    def should_exclude(self, name: str) -> bool:
        """检查是否应排除条目"""
        return any(keyword.lower() in name.lower() for keyword in self.config['exclude_keywords'])

    def parse_iptv_file(self) -> Dict[str, List[Tuple[str, str]]]:
        """解析 IPTV 文件并分类"""
        categorized = defaultdict(list)
        entries = []

        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # 尝试用制表符分割
                    parts = line.split('\t')
                    delimiter = '\t'
                    if len(parts) < 2:
                        # 尝试用逗号分割
                        parts = line.split(',')
                        delimiter = ','
                    if len(parts) < 2:
                        logging.warning(f"无效行格式: {line}")
                        continue
                    name, url = parts[0].strip(), parts[-1].strip()
                    if not name or not url:
                        logging.warning(f"空名称或URL: {line}")
                        continue
                    if not url.startswith(('http://', 'https://')):
                        logging.warning(f"无效 URL 格式: {url}")
                        continue
                    if self.should_exclude(name):
                        logging.info(f"排除条目: {name}")
                        continue
                    entries.append((name, url))
                    logging.debug(f"解析成功: {name} | {url} (分隔符: {delimiter})")
        except Exception as e:
            logging.error(f"解析文件 {self.input_file} 失败: {e}")
            return categorized

        # URL 验证
        if self.config.get('validate_urls', True):
            entries = self.validate_urls(entries)

        # 分类
        for name, url in entries:
            category = self.categorize_entry(name)
            categorized[category].append((name, url))

        return categorized

    def write_output_files(self, categorized: Dict[str, List[Tuple[str, str]]]):
        """生成合并的输出文件，支持 txt 和 m3u 格式"""
        os.makedirs(self.output_dir, exist_ok=True)
        output_formats = self.config.get('output_formats', ['txt', 'm3u'])

        if "txt" in output_formats:
            output_file = os.path.join(self.output_dir, 'output.txt')
            with open(output_file, 'w', encoding='utf-8') as f:
                total_entries = 0
                for category, entries in sorted(categorized.items()):
                    f.write(f"# {category}\n")
                    for name, url in entries:
                        f.write(f'{name}\t{url}\n')
                        total_entries += 1
                    f.write("\n")
            logging.info(f"生成 TXT 文件: {output_file}，总条目数: {total_entries}")

        if "m3u" in output_formats:
            output_file = os.path.join(self.output_dir, 'output.m3u')
            m3u_content = '#EXTM3U\n'
            total_entries = 0
            for category, entries in sorted(categorized.items()):
                m3u_content += f'#EXTINF:-1 group-title="{category}",{category}\n#EXTVLCOPT:network-caching=1000\n\n'
                for name, url in entries:
                    m3u_content += f'#EXTINF:-1 group-title="{category}",{name}\n{url}\n'
                    total_entries += 1
                m3u_content += '\n'
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(m3u_content)
            logging.info(f"生成 M3U 文件: {output_file}，总条目数: {total_entries}")

    def process(self):
        """执行处理流程"""
        logging.info("开始处理 IPTV 列表")
        self.clear_old_failed_links()
        categorized = self.parse_iptv_file()
        self.write_output_files(categorized)
        self.save_links(self.success_links, 'success_links.json')
        self.save_links(self.failed_links, 'failed_links.json')
        elapsed_time = time.time() - self.start_time
        total_entries = sum(len(entries) for entries in categorized.values())
        logging.info(f"处理完成，耗时: {elapsed_time:.2f}秒，总条目数: {total_entries}")

def main():
    input_file = 'iptv_list.txt'
    config_file = 'tvbox/config.json'
    output_dir = 'tvbox'

    if not os.path.exists(input_file):
        logging.error(f"输入文件 {input_file} 不存在")
        return

    processor = IPTVProcessor(input_file, config_file, output_dir)
    processor.process()

if __name__ == '__main__':
    main()
