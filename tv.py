import asyncio
import aiohttp
import aiofiles
import re
import logging
import yaml
import dns.resolver
import os
import psutil
import subprocess
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from urllib.parse import urlparse
from tqdm import tqdm
import sys
import time
import traceback

# 配置日志，记录所有细节到文件和控制台
logging.basicConfig(
    level=logging.DEBUG,  # 使用 DEBUG 级别，确保记录所有操作细节
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8', mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class IPTVScraper:
    def __init__(self, config_file='config/config.yaml'):
        """
        初始化 IPTVScraper，加载配置文件并创建必要的目录。

        参数:
            config_file (str): 配置文件路径，默认为 'config/config.yaml'
        """
        logger.debug("正在初始化 IPTVScraper，配置文件路径: %s", config_file)
        self.config_file = config_file
        self.config = self.load_config()
        self.urls = self.config.get('urls', [])  # 获取配置文件中的 URL 列表
        self.output_dir = self.config.get('output_dir', 'output')  # 输出目录
        self.temp_dir = self.config.get('temp_dir', 'temp_channels')  # 临时目录
        self.regional_dir = self.config.get('regional_dir', '地方频道')  # 地方频道目录
        self.max_concurrent_requests = self.config.get('max_concurrent_requests', 10)  # 最大并发请求数
        self.channels = []  # 存储所有提取的频道
        self.valid_channels = []  # 存储验证通过的频道
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)  # 限制并发请求
        self.start_time = datetime.now()  # 记录脚本开始时间

        # 记录系统信息，便于调试
        logger.debug("系统信息: Python 版本 %s, 平台: %s", sys.version, sys.platform)
        logger.debug("初始 CPU 使用率: %s%%", psutil.cpu_percent())
        logger.debug("初始内存使用量: %s MB", psutil.virtual_memory().used / 1024 / 1024)

        # 创建必要的目录，确保目录存在
        for directory in [self.output_dir, self.temp_dir, self.regional_dir]:
            try:
                os.makedirs(directory, exist_ok=True)
                logger.debug("已创建或验证目录: %s", directory)
            except Exception as e:
                logger.error("无法创建目录 %s: %s", directory, str(e))
                raise RuntimeError(f"目录创建失败: {directory}") from e

    def load_config(self):
        """
        加载 YAML 配置文件。

        返回:
            dict: 配置文件内容，如果失败则返回空字典
        """
        logger.debug("尝试加载配置文件: %s", self.config_file)
        try:
            with open(self.config_file, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                if not config:
                    logger.error("配置文件 %s 为空或格式无效", self.config_file)
                    return {}
                logger.info("成功加载配置文件，包含 %d 个 URL", len(config.get('urls', [])))
                return config
        except FileNotFoundError:
            logger.error("配置文件 %s 未找到", self.config_file)
            return {}
        except yaml.YAMLError as e:
            logger.error("解析 YAML 文件 %s 失败: %s", self.config_file, str(e))
            return {}
        except Exception as e:
            logger.error("加载配置文件 %s 时发生未知错误: %s", self.config_file, str(e))
            return {}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
        before_sleep=lambda retry_state: logger.debug(
            "重试获取 URL (尝试 %d/%d): %s",
            retry_state.attempt_number, 3, retry_state.args[1]
        )
    )
    async def fetch_url(self, session, url):
        """
        从指定 URL 获取内容，支持重试和并发限制。

        参数:
            session (aiohttp.ClientSession): HTTP 会话
            url (str): 要获取的 URL

        返回:
            str: URL 的内容，如果失败则返回 None
        """
        logger.debug("正在获取 URL: %s", url)
        try:
            async with self.semaphore:
                async with session.get(url, timeout=10) as response:
                    logger.debug("收到 %s 的响应，状态码: %d", url, response.status)
                    if response.status == 200:
                        content = await response.text()
                        logger.info("成功获取 %s，内容长度: %d 字节", url, len(content))
                        return content
                    else:
                        logger.warning("URL %s 返回非 200 状态码: %d", url, response.status)
                        return None
        except aiohttp.ClientError as e:
            logger.error("客户端错误，获取 URL %s 失败: %s", url, str(e))
            raise
        except asyncio.TimeoutError:
            logger.error("获取 URL %s 超时", url)
            raise
        except Exception as e:
            logger.error("获取 URL %s 时发生未知错误: %s", url, str(e))
            raise

    async def resolve_url(self, url):
        """
        使用 DNS 解析 URL 的域名，检查其是否可访问。

        参数:
            url (str): 要解析的 URL

        返回:
            bool: 如果域名解析成功返回 True，否则返回 False
        """
        logger.debug("正在解析 URL: %s", url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            logger.error("URL 格式无效，无域名: %s", url)
            return False

        try:
            answers = dns.resolver.resolve(domain, 'A')
            logger.debug("域名 %s 解析成功: %s", domain, [str(a) for a in answers])
            return True
        except dns.resolver.NXDOMAIN:
            logger.warning("域名 %s 不存在", domain)
            return False
        except dns.resolver.Timeout:
            logger.warning("域名 %s 解析超时", domain)
            return False
        except Exception as e:
            logger.error("解析域名 %s 时发生未知错误: %s", domain, str(e))
            return False

    async def check_channel_validity(self, channel):
        """
        使用 FFmpeg 验证频道 URL 是否可播放。

        参数:
            channel (dict): 包含 'url' 和 'name' 键的频道字典

        返回:
            bool: 如果频道有效返回 True，否则返回 False
        """
        url = channel.get('url')
        name = channel.get('name', '未知频道')
        logger.debug("正在验证频道: %s (%s)", name, url)

        if not url:
            logger.warning("频道 %s 无 URL", name)
            return False

        if not await self.resolve_url(url):
            logger.warning("由于 DNS 解析失败，跳过验证频道 %s (%s)", name, url)
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-i', url, '-t', '5', '-f', 'null', '-',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
            if process.returncode == 0:
                logger.info("频道 %s (%s) 验证通过", name, url)
                return True
            else:
                logger.warning("频道 %s (%s) 验证失败: %s", name, url, stderr.decode())
                return False
        except asyncio.TimeoutError:
            logger.warning("验证频道 %s (%s) 超时", name, url)
            return False
        except FileNotFoundError:
            logger.error("未找到 FFmpeg，请确保已安装 FFmpeg")
            return False
        except Exception as e:
            logger.error("验证频道 %s (%s) 时发生未知错误: %s", name, url, str(e))
            return False

    async def extract_channels(self, session, url, index, total_urls):
        """
        从 URL 内容中提取频道信息（如 M3U 播放列表）。

        参数:
            session (aiohttp.ClientSession): HTTP 会话
            url (str): 要处理的 URL
            index (int): 当前 URL 的索引，用于进度跟踪
            total_urls (int): 总 URL 数量
        """
        logger.debug("处理 URL %d/%d: %s", index + 1, total_urls, url)

        if not await self.resolve_url(url):
            logger.warning("由于 DNS 解析失败，跳过 URL: %s", url)
            return

        try:
            content = await self.fetch_url(session, url)
            if not content:
                logger.warning("无法从 URL 获取内容: %s", url)
                return

            lines = content.splitlines()
            current_channel = {}
            for line in lines:
                line = line.strip()
                if not line:
                    logger.debug("跳过空行")
                    continue
                if line.startswith('#EXTINF'):
                    match = re.search(r'tvg-name="([^"]+)"', line)
                    if match:
                        current_channel['name'] = match.group(1)
                        logger.debug("找到频道名称: %s", current_channel['name'])
                    else:
                        logger.debug("EXTINF 行无 tvg-name: %s", line)
                elif line.startswith('http'):
                    current_channel['url'] = line
                    if 'name' in current_channel:
                        self.channels.append(current_channel.copy())
                        logger.debug("添加频道: %s (%s)", current_channel['name'], current_channel['url'])
                        current_channel = {}
                    else:
                        logger.debug("找到无名称的 URL: %s", line)
            logger.warning("完成处理 %d/%d 个 URL，用于频道提取", index + 1, total_urls)
        except Exception as e:
            logger.error("处理 URL %s 的内容时出错: %s", url, str(e))
            logger.debug("错误堆栈: %s", traceback.format_exc())

    async def process_channels(self):
        """
        处理所有 URL，提取并验证频道。
        """
        logger.info("开始从 %d 个 URL 提取频道", len(self.urls))
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i, url in enumerate(self.urls):
                tasks.append(self.extract_channels(session, url, i, len(self.urls)))
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.warning("频道提取完成，提取的频道总数（过滤前）: %d", len(self.channels))

        # 过滤和去重频道
        seen_urls = set()
        unique_channels = []
        for channel in self.channels:
            url = channel.get('url')
            name = channel.get('name', '未知频道')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_channels.append(channel)
                logger.debug("保留唯一频道: %s (%s)", name, url)
            else:
                logger.debug("丢弃重复或无效频道: %s (%s)", name, url)

        self.channels = unique_channels
        logger.warning("过滤和去重后的频道总数: %d", len(self.channels))

        # 验证频道，使用进度条显示
        logger.warning("开始多线程验证 %d 个频道的有效性...", len(self.channels))
        valid_channels = []
        for channel in tqdm(self.channels, desc="验证频道", unit="频道"):
            if await self.check_channel_validity(channel):
                valid_channels.append(channel)

        self.valid_channels = valid_channels
        logger.warning("验证后的有效频道总数: %d", len(self.valid_channels))

    def categorize_channels(self):
        """
        将频道分类为 CCTV、地方频道和未分类频道。

        返回:
            dict: 分类后的频道字典
        """
        logger.debug("正在分类 %d 个有效频道", len(self.valid_channels))
        categorized = {
            'CCTV': [],
            '地方': [],
            'uncategorized': []
        }
        regional_keywords = [
            '北京', '上海', '广东', '浙江', '江苏', '山东', '四川', '湖南', '湖北', '河南',
            '重庆', '安徽', '福建', '甘肃', '广西', '贵州', '海南', '河北', '黑龙江', '江西',
            '吉林', '辽宁', '内蒙古', '宁夏', '青海', '山西', '陕西', '天津', '新疆', '云南'
        ]

        for channel in self.valid_channels:
            name = channel.get('name', '').lower()
            logger.debug("分类频道: %s", name)
            if 'cctv' in name:
                categorized['CCTV'].append(channel)
                logger.debug("分配至 CCTV 分类: %s", name)
            elif any(keyword.lower() in name for keyword in regional_keywords):
                categorized['地方'].append(channel)
                logger.debug("分配至地方频道分类: %s", name)
            else:
                categorized['uncategorized'].append(channel)
                logger.debug("分配至未分类频道: %s", name)

        logger.debug("分类结果: CCTV=%d, 地方=%d, 未分类=%d",
                     len(categorized['CCTV']), len(categorized['地方']), len(categorized['uncategorized']))
        return categorized

    async def save_channels(self):
        """
        将分类后的频道保存到对应的文件中，并合并生成最终的 iptv_list.txt。
        """
        logger.debug("开始保存频道")
        categorized = self.categorize_channels()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.debug("生成输出文件时间戳: %s", timestamp)

        # 保存分类后的频道到各自文件
        for category, channels in categorized.items():
            logger.warning("处理分类: %s，包含 %d 个频道", category, len(channels))
            output_file = os.path.join(self.output_dir, f"{category}_iptv.txt")
            try:
                async with aiofiles.open(output_file, 'w', encoding='utf-8') as file:
                    await file.write(f"更新时间,{timestamp},#genre#\n")
                    for channel in channels:
                        name = channel.get('name', '未知频道')
                        url = channel.get('url', '')
                        await file.write(f"{name},{url}\n")
                        logger.debug("写入频道到 %s: %s (%s)", output_file, name, url)
                logger.info("成功保存 %d 个频道到 %s", len(channels), output_file)
            except Exception as e:
                logger.error("无法保存频道到 %s: %s", output_file, str(e))

        # 单独保存未分类频道
        uncategorized_file = os.path.join(self.output_dir, 'uncategorized_iptv.txt')
        logger.warning("处理未分类频道: %d 个频道", len(categorized['uncategorized']))
        try:
            async with aiofiles.open(uncategorized_file, 'w', encoding='utf-8') as file:
                await file.write(f"更新时间,{timestamp},#genre#\n")
                for channel in categorized['uncategorized']:
                    name = channel.get('name', '未知频道')
                    url = channel.get('url', '')
                    await file.write(f"{name},{url}\n")
                    logger.debug("写入未分类频道: %s (%s)", name, url)
            logger.info("未分类频道保存至: %s", uncategorized_file)
        except Exception as e:
            logger.error("无法保存未分类频道到 %s: %s", uncategorized_file, str(e))

        # 合并所有频道到 iptv_list.txt
        all_channels = []
        for category, channels in categorized.items():
            all_channels.extend(channels)
            logger.debug("从分类 %s 合并 %d 个频道", category, len(channels))

        # 去重合并后的频道
        seen_urls = set()
        unique_channels = []
        for channel in all_channels:
            url = channel.get('url')
            name = channel.get('name', '未知频道')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_channels.append(channel)
                logger.debug("保留 iptv_list.txt 的唯一频道: %s (%s)", name, url)
            else:
                logger.debug("丢弃重复频道: %s (%s)", name, url)

        output_file = os.path.join(self.output_dir, 'iptv_list.txt')
        logger.warning("为 iptv_list.txt 检查和过滤的唯一频道总数: %d", len(unique_channels))
        try:
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as file:
                await file.write(f"更新时间,{timestamp},#genre#\n")
                for channel in unique_channels:
                    name = channel.get('name', '未知频道')
                    url = channel.get('url', '')
                    await file.write(f"{name},{url}\n")
                    logger.debug("写入频道到 iptv_list.txt: %s (%s)", name, url)
            logger.warning("所有地方频道列表已合并、去重并清理，输出保存至: %s", output_file)
        except Exception as e:
            logger.error("无法保存合并频道到 %s: %s", output_file, str(e))

    async def main(self):
        """
        主执行方法，运行整个爬取和处理流程。
        """
        logger.info("开始执行 IPTV 爬取脚本")
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        initial_cpu = psutil.cpu_percent()
        logger.info("初始系统资源 - 内存: %.2f MB, CPU: %.2f%%", initial_memory, initial_cpu)

        try:
            await self.process_channels()
            await self.save_channels()
        except Exception as e:
            logger.error("主执行过程中发生严重错误: %s", str(e))
            logger.debug("错误堆栈: %s", traceback.format_exc())
        finally:
            final_memory = process.memory_info().rss / 1024 / 1024
            final_cpu = psutil.cpu_percent()
            execution_time = (datetime.now() - self.start_time).total_seconds()
            logger.info("最终系统资源 - 内存: %.2f MB, CPU: %.2f%%", final_memory, final_cpu)
            logger.info("总执行时间: %.2f 秒", execution_time)
            logger.warning("IPTV 处理脚本执行完成")

if __name__ == "__main__":
    logger.debug("脚本启动")
    try:
        scraper = IPTVScraper()
        asyncio.run(scraper.main())
    except KeyboardInterrupt:
        logger.warning("用户中断脚本执行")
        sys.exit(1)
    except Exception as e:
        logger.error("脚本执行发生致命错误: %s", str(e))
        logger.debug("错误堆栈: %s", traceback.format_exc())
        sys.exit(1)
    finally:
        logger.debug("脚本执行结束")
