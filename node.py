import json
import base64
import re
import binascii
from urllib.parse import quote, unquote, urlparse
from typing import Dict, Any, Union, Set
import logging
import yaml
from settings import config

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
        elif self.type == 'ss':
            opts = data.get('plugin-opts', {})
            path = opts.get('host', '') + '/' + opts.get('path', '')
        elif self.type == 'ssr':
            path = data.get('obfs-param', '')
        elif self.type == 'trojan':
            path = data.get('sni', '') + ':'
            net = data.get('network', '')
            if net == 'ws':
                opts = data.get('ws-opts', {})
                path += opts.get('headers', {}).get('Host', '') + '/' + opts.get('path', '')
            elif net == 'grpc':
                path += data.get('grpc-opts', {}).get('grpc-service-name', '')
        elif self.type == 'vless':
            path = data.get('sni', '') + ':'
            net = data.get('network', '')
            if net == 'ws':
                opts = data.get('ws-opts', {})
                path += opts.get('headers', {}).get('Host', '') + '/' + opts.get('path', '')
            elif net == 'grpc':
                path += data.get('grpc-opts', {}).get('grpc-service-name', '')
        elif self.type == 'hysteria2':
            path = data.get('sni', '') + ':' + data.get('obfs-password', '') + ':'
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
            if v['net'] == 'ws':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['headers'] = {'Host': v['host']}
                self.data['ws-opts'] = opts
            elif v['net'] == 'h2':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['host'] = v['host'].split(',')
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}
        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            if '#' in srvname:
                srv, name = srvname.split('#', 1)
            else:
                srv, name = srvname, ''
            if ':' not in srv:
                logger.error(f"无效的 ss:// 格式，缺少端口：{url}")
                raise NotANode(url)
            server, port = srv.rsplit(':', 1)
            try:
                port = int(port)
            except ValueError:
                logger.error(f"无效的端口号：{port} in {url}")
                raise NotANode(url)
            info = '@'.join(info)
            try:
                info = b64decodes_safe(info)
            except (binascii.Error, UnicodeDecodeError) as e:
                logger.error(f"无法解码 ss:// 加密信息：{info}")
                raise NotANode(url)
            if ':' in info:
                cipher, passwd = info.split(':', 1)
            else:
                cipher, passwd = info, ''
            self.data = {
                'name': unquote(name),
                'server': server,
                'port': port,
                'type': 'ss',
                'password': passwd,
                'cipher': cipher
            }
        elif self.type == 'ssr':
            if '?' in url:
                parts = dt.split(':')
            else:
                try:
                    parts = b64decodes_safe(dt).split(':')
                except (binascii.Error, UnicodeDecodeError):
                    raise NotANode(url)
            try:
                passwd, info = parts[-1].split('/?')
                passwd = b64decodes_safe(passwd)
            except:
                raise NotANode(url)
            self.data = {
                'type': 'ssr',
                'server': parts[0],
                'port': parts[1],
                'protocol': parts[2],
                'cipher': parts[3],
                'obfs': parts[4],
                'password': passwd,
                'name': ''
            }
            for kv in info.split('&'):
                k_v = kv.split('=')
                if len(k_v) != 2:
                    k, v = k_v[0], ''
                else:
                    k, v = k_v
                if k == 'remarks':
                    self.data['name'] = v
                elif k == 'group':
                    self.data['group'] = v
                elif k == 'obfsparam':
                    self.data['obfs-param'] = v
                elif k == 'protoparam':
                    self.data['protocol-param'] = v
        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {
                'name': unquote(parsed.fragment),
                'server': parsed.hostname,
                'port': parsed.port,
                'type': 'trojan',
                'password': unquote(parsed.username)
            }
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k, v = kv.split('=')
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni':
                        self.data['sni'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
        elif self.type == 'vless':
            parsed = urlparse(url)
            self.data = {
                'name': unquote(parsed.fragment),
                'server': parsed.hostname,
                'port': parsed.port,
                'type': 'vless',
                'uuid': unquote(parsed.username)
            }
            self.data['tls'] = False
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k, v = kv.split('=')
                    if k in ('allowInsecure', 'insecure'):
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'sni':
                        self.data['servername'] = v
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
                    elif k == 'flow':
                        if v.endswith('-udp443'):
                            self.data['flow'] = v
                        else:
                            self.data['flow'] = v + '!'
                    elif k == 'fp':
                        self.data['client-fingerprint'] = v
                    elif k == 'security' and v == 'tls':
                        self.data['tls'] = True
                    elif k == 'pbk':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['public-key'] = v
                    elif k == 'sid':
                        if 'reality-opts' not in self.data:
                            self.data['reality-opts'] = {}
                        self.data['reality-opts']['short-id'] = v
        elif self.type == 'hysteria2':
            parsed = urlparse(url)
            self.data = {
                'name': unquote(parsed.fragment),
                'server': parsed.hostname,
                'type': 'hysteria2',
                'password': unquote(parsed.username)
            }
            if ':' in parsed.netloc:
                ports = parsed.netloc.split(':')[1]
                if ',' in ports:
                    self.data['port'], self.data['ports'] = ports.split(',', 1)
                else:
                    self.data['port'] = ports
                try:
                    self.data['port'] = int(self.data['port'])
                except ValueError:
                    self.data['port'] = 443
            else:
                self.data['port'] = 443
            self.data['tls'] = False
            if parsed.query:
                k = v = ''
                for kv in parsed.query.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=')
                    else:
                        v += '&' + kv
                    if k == 'insecure':
                        self.data['skip-cert-verify'] = (v != '0')
                    elif k == 'alpn':
                        self.data['alpn'] = unquote(v).split(',')
                    elif k in ('sni', 'obfs', 'obfs-password'):
                        self.data[k] = v
                    elif k == 'fp':
                        self.data['fingerprint'] = v
        else:
            logger.error(f"不支持的协议类型：{self.type}")
            raise UnsupportedType(self.type)

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
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError:
                        pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://' + b64encodes(json.dumps(v, ensure_ascii=False))
        elif self.type == 'ss':
            passwd = b64encodes_safe(data['cipher'] + ':' + data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        elif self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server', 'port', 'protocol', 'cipher', 'obfs')]) +
                   b64encodes_safe(self.data['password']) +
                   f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param', 'obfsparam'), ('protocol-param', 'protoparam'), ('group', 'group')):
                if k in self.data:
                    ret += '&' + urlk + '=' + b64encodes_safe(self.data[k])
            return "ssr://" + ret
        elif self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError:
                            pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&') + '#' + name
            return ret
        elif self.type == 'vless':
            passwd = quote(data['uuid'])
            name = quote(data['name'])
            ret = f"vless://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'servername' in data:
                ret += f"sni={data['servername']}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError:
                            pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            if 'flow' in data:
                flow = data['flow']
                if flow.endswith('!'):
                    ret += f"flow={flow[:-1]}&"
                else:
                    ret += f"flow={flow}-udp443&"
            if 'client-fingerprint' in data:
                ret += f"fp={data['client-fingerprint']}&"
            if 'tls' in data and data['tls']:
                ret += f"security=tls&"
            elif 'reality-opts' in data:
                opts = data['reality-opts']
                ret += f"security=reality&pbk={opts.get('public-key', '')}&sid={opts.get('short-id', '')}&"
            ret = ret.rstrip('&') + '#' + name
            return ret
        elif self.type == 'hysteria2':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"hysteria2://{passwd}@{data['server']}:{data['port']}"
            if 'ports' in data:
                ret += ',' + data['ports']
            ret += '?'
            if 'skip-cert-verify' in data:
                ret += f"insecure={int(data['skip-cert-verify'])}&"
            if 'alpn' in data:
                ret += f"alpn={quote(','.join(data['alpn']))}&"
            if 'fingerprint' in data:
                ret += f"fp={data['fingerprint']}&"
            for k in ('sni', 'obfs', 'obfs-password'):
                if k in data:
                    ret += f"{k}={data[k]}&"
            ret = ret.rstrip('&') + '#' + name
            return ret
        logger.error(f"不支持的协议类型：{self.type}")
        raise UnsupportedType(self.type)

    @property
    def clash_data(self) -> DATA_TYPE:
        """生成 Clash 配置文件数据"""
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str ' + ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(config["default_uuid"]):
            ret['uuid'] = config["default_uuid"]
        if 'group' in ret:
            del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        if self.type == 'vless' and 'flow' in ret:
            if ret['flow'].endswith('-udp443'):
                ret['flow'] = ret['flow'][:-7]
            elif ret['flow'].endswith('!'):
                ret['flow'] = ret['flow'][:-1]
        if 'alpn' in ret and isinstance(ret['alpn'], str):
            ret['alpn'] = ret['alpn'].replace(' ', '').split(',')
        return ret

    def supports_meta(self, noMeta: bool = False) -> bool:
        """检查节点是否支持 Clash Meta"""
        if self.isfake:
            return False
        if self.type == 'vmess':
            supported = config["clash_cipher_vmess"]
        elif self.type in ('ss', 'ssr'):
            supported = config["clash_cipher_ss"]
        elif self.type in ('trojan', 'vless', 'hysteria2') and not noMeta:
            return True
        else:
            return False
        if 'network' in self.data and self.data['network'] in ('h2', 'grpc'):
            self.data['tls'] = True
        if 'cipher' not in self.data or not self.data['cipher']:
            return True
        if self.data['cipher'] not in supported:
            return False
        try:
            if self.type == 'ssr':
                if 'obfs' in self.data and self.data['obfs'] not in config["clash_ssr_obfs"]:
                    return False
                if 'protocol' in self.data and self.data['protocol'] not in config["clash_ssr_protocol"]:
                    return False
            if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] and not self.data['plugin-opts']['mode']:
                return False
        except Exception as e:
            logger.error(f"无法验证 Clash 节点：{e}")
            return False
        return True

    def supports_clash(self, meta: bool = False) -> bool:
        """检查节点是否支持 Clash"""
        if meta:
            return self.supports_meta()
        if self.type == 'vless' or self.data['type'] == 'vless':
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
    """Base64 编码"""
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s: str) -> str:
    """Base64 URL 安全编码"""
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s: str) -> str:
    """Base64 解码"""
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error) as e:
        logger.error(f"Base64 解码失败：{e}")
        raise

def b64decodes_safe(s: str) -> str:
    """Base64 URL 安全解码"""
    ss = s + '=' * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except (UnicodeDecodeError, binascii.Error) as e:
        logger.error(f"Base64 安全解码失败：{e}")
        raise
