```python
import requests
from requests_file import FileAdapter
import json
import yaml
from typing import Union, List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
from config import config

logger = logging.getLogger(__name__)

class Source:
    """订阅源类，用于抓取和解析订阅内容"""
    def __init__(self, url: Union[str, callable]) -> None:
        """
        初始化订阅源。
        Args:
            url: 订阅 URL 或动态生成函数。
        """
        self.url: str = url if isinstance(url, str) else f"dynamic://{url.__name__}"
        self.url_source: Optional[callable] = url if callable(url) else None
        self.content: Union[str, List[str], int, None] = None
        self.sub: Union[List[str], List[Dict[str, str]], None] = None
        self.cfg: Dict[str, Any] = {}

    def gen_url(self) -> None:
        """生成动态 URL"""
        if not isinstance(self.url_source, str):
            return
        tags = self.url_source.split()
        url = tags.pop()
        date = datetime.now()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+':
                break
            if tag == '+date':
                url = date.strftime(url)
                date -= timedelta(days=1)
        self.url = url

    def get(self, depth: int = 2) -> None:
        """抓取订阅内容"""
        if self.content:
            return
        try:
            if self.url.startswith("dynamic://"):
                self.content = self.url_source()
            else:
                if '#' in self.url:
                    segs = self.url.split('#')
                    self.cfg = dict([_.split('=', 1) for _ in segs[-1].split('&')])
                    if 'max' in self.cfg:
                        try:
                            self.cfg['max'] = int(self.cfg['max'])
                        except ValueError:
                            logger.error("最大节点数限制不是整数")
                            del self.cfg['max']
                    if 'ignore' in self.cfg:
                        self.cfg['ignore'] = [_ for _ in self.cfg['ignore'].split(',') if _.strip()]
                    self.url = '#'.join(segs[:-1])
                with session.get(self.url, stream=True, timeout=(config["fetch_timeout"]["connect"], config["fetch_timeout"]["read"])) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            logger.warning(f"'{self.url}' 抓取失败，状态码：{r.status_code}，重试...")
                            self.gen_url()
                            self.get(depth - 1)
                        else:
                            self.content = r.status_code
                        return
                    self.content = self._download(r)
        except requests.exceptions.RequestException as e:
            self.content = -1
            logger.error(f"抓取 '{self.url}' 失败：{e}")
        except Exception as e:
            self.content = -2
            logger.error(f"抓取 '{self.url}' 时发生错误：{e}")

    def _download(self, r: requests.Response) -> str:
        """下载响应内容"""
        content = ""
        pending = None
        for chunk in r.iter_content(chunk_size=8192):
            if pending is not None:
                chunk = pending + chunk
                pending = None
            try:
                content += chunk.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                pending = chunk
        if pending:
            content += pending.decode('utf-8', errors='ignore')
        return content

    def parse(self) -> None:
        """解析订阅内容"""
        if not isinstance(self.content, str):
            self.sub = []
            logger.error(f"无效的内容类型 for '{self.url}': {type(self.content)}")
            return
        text = self.content.strip()
        if not text:
            self.sub = []
            logger.error(f"空内容 from '{self.url}'")
            return

        try:
            data = json.loads(text)
            if isinstance(data, list):
                self.sub = data
            elif isinstance(data, dict) and 'proxies' in data:
                self.sub = data['proxies']
            else:
                self.sub = []
                logger.error(f"JSON 格式不包含有效节点列表 for '{self.url}'")
            return
        except json.JSONDecodeError:
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and 'proxies' in data:
                    self.sub = data['proxies']
                elif isinstance(data, list):
                    self.sub = data
                else:
                    self.sub = []
                    logger.error(f"YAML 格式不包含有效节点列表 for '{self.url}'")
                return
            except yaml.YAMLError:
                # ... 其他解析逻辑
                self.sub = []
```
