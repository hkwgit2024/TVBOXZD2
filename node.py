```python
import json
import base64
import re
import binascii
from urllib.parse import quote, unquote, urlparse
from typing import Dict, Any, Union, Set
import logging
import yaml

from config import config

logger = logging.getLogger(__name__)

class Node:
    """代理节点类，用于解析和处理代理节点信息"""
    names: Set[str] = set()
    DATA_TYPE = Dict[str, Any]
    
    VMESS_EXAMPLE = {
        "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
        "net": "tcp", "type": "none", "tls": "", "id": config["default_uuid"]
    }
    
    CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id',
                   'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
    VMESS2CLASH = {v: k for k, v in CLASH2VMESS.items()}

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        """
        初始化节点对象。
        Args:
            data: 节点数据（字典或 URL 字符串）。
        Raises:
            TypeError: 如果输入数据类型无效。
            NotANode: 如果 URL 格式无效。
            UnsupportedType: 如果协议类型不受支持。
        """
        self.data: Node.DATA_TYPE = {}
        if isinstance(data, dict):
            self.data = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else:
            logger.error(f"不支持的输入类型：{type(data)}")
            raise TypeError(f"不支持的输入类型：{type(data)}")
        
        if not self.data.get('name'):
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.name: str = self.data['name']

    def __str__(self):
        return self.url

    def __hash__(self):
        try:
            path = self._build_hash_path()
            hashstr = f"{self.type}:{self.data['server']}:{self.data['port']}:{path}"
            return hash(hashstr)
        except Exception as e:
            logger.error(f"节点 Hash 计算失败：{e}")
            return hash('__ERROR__')

    def __eq__(self, other: Any):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        return False

    def _build_hash_path(self) -> str:
        """构建用于计算哈希的路径字符串"""
        data = self.data
        path = ""
        if self.type == 'vmess':
            net = data.get('network', '')
            path = net + ':'
            if net == 'ws':
                opts = data.get('ws-opts', {})
                path += opts.get('headers', {}).get('Host', '')
                path += '/' + opts.get('path', '')
            elif net == 'h2':
                opts = data.get('h2-opts', {})
                path += ','.join(opts.get('host', []))
                path += '/' + opts.get('path', '')
            elif net == 'grpc':
                path += data.get('grpc-opts', {}).get('grpc-service-name', '')
        # ... 其他协议类型的路径处理
        path += '@' + ','.join(data.get('alpn', [])) + '@' + data.get('password', '') + data.get('uuid', '')
        return path

    def load_url(self, url: str) -> None:
        """从 URL 解析节点信息"""
        try:
            self.type, dt = url.split("://", 1)
        except ValueError:
            logger.error(f"无效的节点 URL：{url}")
            raise NotANode(url)

        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type + '://' + url.split("://")[1]
        if self.type == 'hy2':
            self.type = 'hysteria2'

        if self.type == 'vmess':
            v = self.VMESS_EXAMPLE.copy()
            try:
                v.update(json.loads(b64decodes(dt)))
            except Exception as e:
                logger.error(f"解析 vmess URL 失败：{e}")
                raise UnsupportedType('vmess', str(e))
            self.data = {self.VMESS2CLASH[key]: val for key, val in v.items() if key in self.VMESS2CLASH}
            self.data['tls'] = v['tls'] == 'tls'
            self.data['alterId'] = int(self.data['alterId'])
            # ... 其他 vmess 处理逻辑
        elif self.type == 'ss':
            # ... Shadowsocks 解析逻辑
            pass
        # ... 其他协议类型处理

    def format_name(self, max_len: int = 30) -> None:
        """格式化节点名称"""
        self.data['name'] = self.name
        for word in config["banned_words"]:
            self.data['name'] = self.data['name'].replace(word, '*' * len(word))
        if len(self.data['name']) > max_len:
            self.data['name'] = self.data['name'][:max_len] + '...'
        if self.data['name'] in Node.names:
            i = 0
            new = self.data['name']
            while new in Node.names:
                i += 1
                new = f"{self.data['name']} #{i}"
            self.data['name'] = new

    @property
    def isfake(self) -> bool:
        """检查节点是否为假节点"""
        try:
            if 'server' not in self.data or '.' not in self.data['server']:
                return True
            if self.data['server'] in config["fake_ips"]:
                return True
            if int(str(self.data['port'])) < 20:
                return True
            for domain in config["fake_domains"]:
                if self.data['server'] == domain.lstrip('.') or self.data['server'].endswith(domain):
                    return True
            if 'sni' in self.data and 'google.com' in self.data['sni'].lower():
                self.data['sni'] = 'www.bing.com'
                return True
        except Exception as e:
            logger.error(f"无法验证节点：{e}")
            return True
        return False

    @property
    def url(self) -> str:
        """生成节点的 URL 表示"""
        data = self.data
        if self.type == 'vmess':
            v = self.VMESS_EXAMPLE.copy()
            for key, val in data.items():
                if key in self.CLASH2VMESS:
                    v[self.CLASH2VMESS[key]] = val
            # ... 其他 vmess URL 生成逻辑
            return 'vmess://' + b64encodes(json.dumps(v, ensure_ascii=False))
        # ... 其他协议类型 URL 生成
        logger.error(f"不支持的协议类型：{self.type}")
        raise UnsupportedType(self.type)

    def supports_meta(self, noMeta: bool = False) -> bool:
        """检查节点是否支持 Clash Meta"""
        if self.isfake:
            return False
        supported = config["clash_cipher_vmess"] if self.type == 'vmess' else config["clash_cipher_ss"]
        if self.type in ('trojan', 'vless', 'hysteria2') and not noMeta:
            return True
        # ... 其他支持性检查逻辑
        return True

    def supports_clash(self, meta: bool = False) -> bool:
        """检查节点是否支持 Clash"""
        if meta:
            return self.supports_meta()
        if self.type == 'vless':
            return False
        return self.supports_meta(noMeta=True)

    def supports_ray(self) -> bool:
        """检查节点是否支持 V2Ray"""
        return not self.isfake

class UnsupportedType(Exception):
    pass

class NotANode(Exception):
    pass

def b64encodes(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str) -> str:
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error) as e:
        logger.error(f"Base64 解码失败：{e}")
        raise

def b64decodes_safe(s: str) -> str:
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error) as e:
        logger.error(f"Base64 安全解码失败：{e}")
        raise
```
