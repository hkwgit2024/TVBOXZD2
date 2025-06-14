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
        self.input_hash_file = os.path.join(self.output_dir, 'input_hash.json')
        self.config = self.load_config()
        self.success_links = self.load_links('success_links.json')
        self.failed_links = self.load_links('failed_links.json')
        self.start_time = time.time()

    def load_config(self) -> Dict:
        """加载并校验配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config
        except Exception as e:
            logging.error(f"加载配置文件 {self.config_file} 失败: {e}")
            return {}

    def load_links(self, file_name: str) -> Dict:
        """加载 JSON 文件"""
        file_path = os.path.join(self.output_dir, file_name)
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"加载文件 {file_path} 失败: {e}")
        return {}

    def save_links(self, links: Dict, file_name: str):
        """保存 JSON 文件"""
        file_path = os.path.join(self.output_dir, file_name)
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(links, f, ensure_ascii=False, indent=2)
            logging.info(f"保存 {file_name} 成功")
        except Exception as e:
            logging.error(f"保存文件 {file_path} 失败: {e}")

    def should_exclude(self, name: str, url: str = "") -> bool:
        """检查是否应排除条目，检查名称和URL的域名及路径"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()  # 获取域名（如 vd3.bdstatic.com）
        full_url = url.lower()  # 完整 URL 检查
        for keyword in self.config.get('exclude_keywords', []):
            keyword = keyword.lower()
            if (keyword in name.lower() or
                keyword == domain or
                keyword in full_url):
                return True
        return False

    def parse_iptv_file(self) -> Dict[str, List[Tuple[str, str]]]:
        """解析 IPTV 列表文件"""
        categorized = defaultdict(list)
        entries = []
        invalid_lines_file = os.path.join(self.output_dir, 'invalid_lines.txt')
        invalid_lines = []

        # 检查输入文件哈希，跳过未更改的文件
        current_hash = self.get_file_hash(self.input_file)
        saved_hash = self.load_links(self.input_hash_file).get('hash', '')
        if current_hash == saved_hash:
            logging.info("输入文件未更改，跳过处理")
            return categorized

        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    delimiter = '\t'
                    if len(parts) < 2:
                        parts = line.split(',')
                        delimiter = ','
                    if len(parts) < 2:
                        invalid_lines.append(f"无效行格式: {line}")
                        continue
                    name, url = parts[0].strip(), parts[-1].strip()
                    if not name or not url:
                        invalid_lines.append(f"空名称或URL: {line}")
                        continue
                    if not url.startswith(('http://', 'https://')):
                        invalid_lines.append(f"无效 URL 格式: {url}")
                        continue
                    if self.should_exclude(name, url):
                        logging.info(f"排除条目: {name} | {url}")
                        continue
                    entries.append((name, url))
                    logging.debug(f"解析成功: {name} | {url} (分隔符: {delimiter})")
        except Exception as e:
            logging.error(f"解析文件 {self.input_file} 失败: {e}")
            return categorized

        # 保存无效行报告
        if invalid_lines:
            with open(invalid_lines_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(invalid_lines))
            logging.info(f"生成无效行报告: {invalid_lines_file}")

        # 保存新哈希
        self.save_links({'hash': current_hash}, self.input_hash_file)

        # 分类条目（假设按名称前缀分组）
        for name, url in entries:
            category = name.split('_')[0] if '_' in name else '其他'
            categorized[category].append((name, url))
        return categorized

    def get_file_hash(self, file_path: str) -> str:
        """计算文件内容哈希"""
        if not os.path.exists(file_path):
            return ""
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def validate_url(self, url: str) -> bool:
        """验证 URL 是否可访问"""
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def validate_urls(self, entries: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """多线程验证 URL"""
        valid_entries = []
        failed_urls_file = os.path.join(self.output_dir, 'failed_urls.txt')
        failed_urls = []
        current_time = time.time()

        with ThreadPoolExecutor(max_workers=self.config.get('max_threads', 10)) as executor:
            future_to_entry = {executor.submit(self.validate_url, url): (name, url)
                               for name, url in entries}
            for future in as_completed(future_to_entry):
                name, url = future_to_entry[future]
                url_hash = self.get_url_hash(url)
                try:
                    if future.result():
                        valid_entries.append((name, url))
                        self.success_links[url_hash] = {
                            'name': name,
                            'url': url,
                            'timestamp': current_time
                        }
                        logging.info(f"验证成功: {url}")
                    else:
                        failed_urls.append(f"验证失败: {url} ({name})")
                        self.failed_links[url_hash] = {
                            'name': name,
                            'url': url,
                            'timestamp': current_time
                        }
                        logging.info(f"验证失败，记录: {url}")
                except Exception as e:
                    logging.error(f"验证 {url} 失败: {e}")
                    failed_urls.append(f"验证失败: {url} ({name})")
                    self.failed_links[url_hash] = {
                        'name': name,
                        'url': url,
                        'timestamp': current_time
                    }

        # 保存失败 URL 报告
        if failed_urls:
            with open(failed_urls_file, 'a', encoding='utf-8') as f:
                f.write('\n'.join(failed_urls) + '\n')
            logging.info(f"追加失败 URL 报告: {failed_urls_file}")

        return valid_entries

    def get_url_hash(self, url: str) -> str:
        """生成 URL 的哈希值"""
        return hashlib.md5(url.encode('utf-8')).hexdigest()

    def clear_old_failed_links(self):
        """清理过期的失败链接并重新验证"""
        clear_days = self.config.get('clear_failed_links_days', 30)
        if not clear_days:
            return
        current_time = time.time()
        updated_failed_links = {}
        to_revalidate = []
        for url_hash, data in self.failed_links.items():
            timestamp = data.get('timestamp', 0)
            if (current_time - timestamp) / 86400 < clear_days:
                updated_failed_links[url_hash] = data
            else:
                to_revalidate.append((data['name'], data['url'], url_hash))
        if to_revalidate:
            logging.info(f"重新验证 {len(to_revalidate)} 个过期失败链接")
            valid_entries = self.validate_urls([(name, url) for name, url, _ in to_revalidate])
            for name, url in valid_entries:
                url_hash = self.get_url_hash(url)
                self.success_links[url_hash] = {
                    'name': name,
                    'url': url,
                    'timestamp': current_time
                }
                logging.info(f"失败链接恢复: {url}")
        self.failed_links = updated_failed_links
        self.save_links(self.failed_links, 'failed_links.json')

    def write_output_files(self, categorized: Dict[str, List[Tuple[str, str]]]):
        """生成输出文件"""
        output_formats = self.config.get('output_formats', ['txt', 'm3u'])
        total_entries = 0
        txt_content = []
        m3u_content = ["#EXTM3U"]

        for category, entries in categorized.items():
            txt_content.append(f"{category},#genre#")
            for name, url in entries:
                total_entries += 1
                if "txt" in output_formats:
                    txt_content.append(f"{name},{url}")
                if "m3u" in output_formats:
                    m3u_content.append(f"#EXTINF:-1,{name}\n{url}")

        if "txt" in output_formats:
            txt_file = os.path.join(self.output_dir, 'output.txt')
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(txt_content))
            logging.info(f"生成 TXT 文件: {txt_file}，总条目数: {total_entries}")

        if "m3u" in output_formats:
            m3u_file = os.path.join(self.output_dir, 'output.m3u')
            with open(m3u_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(m3u_content))
            logging.info(f"生成 M3U 文件: {m3u_file}，总条目数: {total_entries}")

    def process(self):
        """主处理流程"""
        logging.info("开始处理 IPTV 列表")
        self.clear_old_failed_links()
        categorized = self.parse_iptv_file()
        valid_entries = []
        for category, entries in categorized.items():
            valid_entries.extend(self.validate_urls(entries))
        new_categorized = defaultdict(list)
        for name, url in valid_entries:
            category = name.split('_')[0] if '_' in name else '其他'
            new_categorized[category].append((name, url))
        self.write_output_files(new_categorized)
        self.save_links(self.success_links, 'success_links.json')
        self.save_links(self.failed_links, 'failed_links.json')
        elapsed_time = time.time() - self.start_time
        logging.info(f"处理完成，耗时: {elapsed_time:.2f}秒，总条目数: {sum(len(v) for v in new_categorized.values())}")

if __name__ == "__main__":
    processor = IPTVProcessor(
        input_file="tvbox/iptv_list.txt",
        config_file="tvbox/config.json",
        output_dir="tvbox"
    )
    processor.process()
