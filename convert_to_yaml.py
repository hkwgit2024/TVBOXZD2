import requests
import base64
import json
import yaml
import os
import re
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib

# GitHub raw 链接列表
urls = [
  
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/input/v.txt"

]

# Clash/Mihomo 配置模板 (基础结构，代理和代理组将动态填充)
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "geodata-mode": True,
    "geox-url": {
        "geoip": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat",
        "mmdb": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb"
    },
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29"
        ],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True,
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        "fallback": [
            "https://doh.dns.sb/dns-query",
            "https://dns.cloudflare.com/dns-query",
            "https://dns.twnic.tw/dns-query",
            "tls://8.8.4.4:853"
        ],
        "fallback-filter": {
            "geoip": True,
            "ipcidr": [
                "240.0.0.0/4",
                "0.0.0.0/32"
            ]
        }
    },
    "rules": [
        "DOMAIN,app.adjust.com,DIRECT",
        "DOMAIN,bdtj.tagtic.cn,DIRECT",
        "DOMAIN,log.mmstat.com,DIRECT",
        "DOMAIN,sycm.mmstat.com,DIRECT",
        "DOMAIN-SUFFIX,blog.google,DIRECT",
        "DOMAIN-SUFFIX,googletraveladservices.com,DIRECT",
        "DOMAIN,dl.google.com,DIRECT",
        "DOMAIN,dl.l.google.com,DIRECT",
        "DOMAIN,fonts.googleapis.com,DIRECT",
        "DOMAIN,fonts.gstatic.com,DIRECT",
        "DOMAIN,mtalk.google.com,DIRECT",
        "DOMAIN,alt1-mtalk.google.com,DIRECT",
        "DOMAIN,alt2-mtalk.google.com,DIRECT",
        "DOMAIN,alt3-mtalk.google.com,DIRECT",
        "DOMAIN,alt4-mtalk.google.com,DIRECT",
        "DOMAIN,alt5-mtalk.google.com,DIRECT",
        "DOMAIN,alt6-mtalk.google.com,DIRECT",
        "DOMAIN,alt7-mtalk.google.com,DIRECT",
        "DOMAIN,alt8-mtalk.google.com,DIRECT",
        "DOMAIN,fairplay.l.qq.com,DIRECT",
        "DOMAIN,livew.l.qq.com,DIRECT",
        "DOMAIN,vd.l.qq.com,DIRECT",
        "DOMAIN,analytics.strava.com,DIRECT",
        "DOMAIN,msg.umeng.com,DIRECT",
        "DOMAIN,msg.umengcloud.com,DIRECT",
    ]
}

# 配置请求重试机制
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))

# 检查是否为有效的 Base64 字符串
def is_valid_base64(s):
    s_stripped = s.strip()
    if not s_stripped:
        return False
    # Quick check for typical base64 chars, more robust check is in try-except
    if not re.match(r'^[A-Za-z0-9+/=]+$', s_stripped):
        return False
    try:
        if len(s_stripped) % 4 == 1: # Invalid padding
            return False
        base64.urlsafe_b64decode(s_stripped + '==' * (-len(s_stripped) % 4))
        return True
    except (base64.binascii.Error, UnicodeDecodeError):
        return False

# 生成节点指纹
def generate_node_fingerprint(node):
    fingerprint_data = []
    node_type = node.get('type')
    fingerprint_data.append(node_type)
    fingerprint_data.append(node.get('server'))
    fingerprint_data.append(str(node.get('port')))

    if node_type == 'ss':
        fingerprint_data.append(node.get('cipher'))
        fingerprint_data.append(node.get('password'))
        if node.get('plugin'):
            fingerprint_data.append(node.get('plugin'))
            fingerprint_data.append(node.get('obfs-mode'))
            fingerprint_data.append(node.get('obfs-host'))
            fingerprint_data.append(node.get('network'))
            fingerprint_data.append(str(node.get('tls')))
            fingerprint_data.append(node.get('ws-path'))
            if 'ws-headers' in node and 'Host' in node['ws-headers']:
                fingerprint_data.append(node['ws-headers']['Host'])

    elif node_type == 'ssr':
        fingerprint_data.append(node.get('protocol'))
        fingerprint_data.append(node.get('obfs'))
        fingerprint_data.append(node.get('cipher'))
        fingerprint_data.append(node.get('password'))
        fingerprint_data.append(node.get('obfs-param'))
        fingerprint_data.append(node.get('protocol-param'))

    elif node_type == 'vmess':
        fingerprint_data.append(node.get('uuid'))
        fingerprint_data.append(str(node.get('alterId')))
        fingerprint_data.append(node.get('cipher'))
        fingerprint_data.append(node.get('network'))
        fingerprint_data.append(str(node.get('tls')))
        fingerprint_data.append(node.get('sni'))
        fingerprint_data.append(node.get('ws-path'))
        fingerprint_data.append(node.get('grpc-service-name'))
        if 'ws-headers' in node and 'Host' in node['ws-headers']:
            fingerprint_data.append(node['ws-headers']['Host'])

    elif node_type == 'vless':
        fingerprint_data.append(node.get('uuid'))
        fingerprint_data.append(node.get('flow'))
        fingerprint_data.append(node.get('network'))
        fingerprint_data.append(str(node.get('tls')))
        fingerprint_data.append(node.get('sni'))
        fingerprint_data.append(node.get('ws-path'))
        fingerprint_data.append(node.get('grpc-service-name'))
        if 'ws-headers' in node and 'Host' in node['ws-headers']:
            fingerprint_data.append(node['ws-headers']['Host'])

    elif node_type == 'trojan':
        fingerprint_data.append(node.get('password'))
        fingerprint_data.append(str(node.get('tls')))
        fingerprint_data.append(node.get('sni'))
        fingerprint_data.append(str(node.get('alpn')))
        fingerprint_data.append(node.get('network'))
        fingerprint_data.append(node.get('ws-path'))
        fingerprint_data.append(node.get('grpc-service-name'))
        if 'ws-headers' in node and 'Host' in node['ws-headers']:
            fingerprint_data.append(node['ws-headers']['Host'])
            
    elif node_type == 'hysteria2':
        fingerprint_data.append(node.get('password'))
        fingerprint_data.append(str(node.get('tls')))
        fingerprint_data.append(node.get('sni'))
        fingerprint_data.append(str(node.get('alpn')))
        fingerprint_data.append(node.get('obfs'))
        fingerprint_data.append(node.get('obfs-password'))

    data_string = '_'.join([str(item) for item in fingerprint_data if item is not None and str(item).strip() != ''])
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

# 解析 Shadowsocks (ss://) 链接
def parse_ss_link(link, index, url_filename):
    try:
        if not link.startswith('ss://'):
            return None
        parts_raw = link.split('://', 1)[1]
        name_part = ''
        if '#' in parts_raw:
            parts_raw, name_part = parts_raw.rsplit('#', 1)
        
        server_info_part = parts_raw
        encoded_part_and_maybe_host = parts_raw.split('@')[0]
        if '@' in parts_raw:
            _encoded_part_unused, server_info_part = parts_raw.split('@', 1)
        
        decoded_b64 = base64.urlsafe_b64decode(encoded_part_and_maybe_host + '==' * (-len(encoded_part_and_maybe_host) % 4)).decode('utf-8', errors='ignore')
        method, password = decoded_b64.rsplit(':', 1)
        
        server_addr_port_part = server_info_part.split('?')[0]
        server, port_str = server_addr_port_part.split(':')
        port = int(re.sub(r'[^0-9]', '', port_str))

        if not (method and password and server and port):
            return None
        
        name = name_part if name_part else f"ss-{url_filename}-{server}-{port}-{index}"
        
        config = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
        if '?' in server_info_part:
            params = parse_qs(server_info_part.split('?', 1)[1])
            if params.get('plugin', [''])[0]:
                plugin = params['plugin'][0]
                config['plugin'] = plugin.split(';')[0]
                if ';' in plugin:
                    plugin_opts_str = plugin.split(';', 1)[1]
                    plugin_opts = parse_qs(plugin_opts_str)
                    if config['plugin'] == 'obfs':
                        config['obfs-mode'] = plugin_opts.get('obfs', [''])[0]
                        config['obfs-host'] = plugin_opts.get('obfs-host', [''])[0]
                    elif config['plugin'] == 'v2ray-plugin':
                        config['tls'] = (plugin_opts.get('tls', [''])[0].lower() == 'tls' or plugin_opts.get('tls', [''])[0] == '1')
                        config['network'] = plugin_opts.get('mode', [''])[0] if 'mode' in plugin_opts else 'tcp'
                        if config['network'] == 'ws':
                            config['ws-path'] = plugin_opts.get('path', [''])[0]
                            config['ws-headers'] = {'Host': plugin_opts.get('host', [''])[0]}
                        elif config['network'] == 'grpc':
                            config['grpc-service-name'] = plugin_opts.get('serviceName', [''])[0]
                        
                if config.get('tls') and not config.get('sni'):
                             config['sni'] = plugin_opts.get('host', [''])[0] or server
            
            if 'type' in params and not config.get('network'):
                config['network'] = params.get('type', ['tcp'])[0]
            if 'security' in params and params['security'][0].lower() == 'tls' and not config.get('tls'):
                config['tls'] = True

        return config
    except Exception as e:
        print(f"解析 ss:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 解析 ShadowsocksR (ssr://) 链接
def parse_ssr_link(link, index, url_filename):
    try:
        if not link.startswith('ssr://'):
            return None
        encoded = link[6:].split('#')[0]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        parts = decoded.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        port = int(port)
        try:
            password = base64.urlsafe_b64decode(password + '==' * (-len(password) % 4)).decode('utf-8', errors='ignore')
        except (base64.binascii.Error, UnicodeDecodeError):
            pass

        params = parse_qs(parts[6].lstrip('/?')) if len(parts) > 6 else {}
        name = params.get('remarks', [f"ssr-{url_filename}-{server}-{port}-{index}"])[0]
        try:
            name = base64.urlsafe_b64decode(name + '==' * (-len(name) % 4)).decode('utf-8', errors='ignore')
        except (base64.binascii.Error, UnicodeDecodeError):
            pass

        config = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'obfs': obfs,
            'protocol': protocol,
            'password': password,
            'udp': True
        }
        if params.get('obfsparam', [''])[0]:
            try:
                config['obfs-param'] = base64.urlsafe_b64decode(params.get('obfsparam', [''])[0] + '==' * (-len(params.get('obfsparam', [''])[0]) % 4)).decode('utf-8', errors='ignore')
            except (base64.binascii.Error, UnicodeDecodeError):
                config['obfs-param'] = params.get('obfsparam', [''])[0]
        if params.get('protoparam', [''])[0]:
            try:
                config['protocol-param'] = base64.urlsafe_b64decode(params.get('protoparam', [''])[0] + '==' * (-len(params.get('protoparam', [''])[0]) % 4)).decode('utf-8', errors='ignore')
            except (base64.binascii.Error, UnicodeDecodeError):
                config['protocol-param'] = params.get('protoparam', [''])[0]
        return config
    except Exception as e:
        print(f"解析 ssr:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 解析 Vmess (vmess://) 链接
def parse_vmess_link(link, index, url_filename):
    try:
        if not link.startswith('vmess://'):
            return None
        encoded = link[8:]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        config = json.loads(decoded)
        if not (config.get('add') and config.get('port') and config.get('id')):
            return None
        name = config.get('ps', f"vmess-{url_filename}-{index}")
        
        tls_enabled = False
        if config.get('tls') == 'tls':
            tls_enabled = True
        elif config.get('s') == 'tls':
            tls_enabled = True

        parsed_config = {
            'name': name,
            'type': 'vmess',
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'network': config.get('net', 'tcp'),
            'udp': True,
        }

        if tls_enabled:
            parsed_config['tls'] = True
            parsed_config['sni'] = config.get('host', '') or config.get('add')
            if config.get('allowInsecure') == 1 or config.get('skip-cert-verify'):
                parsed_config['skip-cert-verify'] = True
            if config.get('fp'):
                parsed_config['fingerprint'] = config['fp']

        if parsed_config['network'] == 'ws':
            parsed_config['ws-path'] = config.get('path', '')
            parsed_config['ws-headers'] = {'Host': config.get('host', '')}
        
        if parsed_config['network'] == 'grpc':
            parsed_config['grpc-service-name'] = config.get('serviceName', '')
            parsed_config['grpc-auto-tuning'] = config.get('grpc-auto-tuning', False)

        return parsed_config
    except Exception as e:
        print(f"解析 vmess:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 解析 VLESS (vless://) 链接
def parse_vless_link(link, index, url_filename):
    try:
        if not link.startswith('vless://'):
            return None
        parts = link.split('://', 1)[1]
        uuid_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        uuid, server_port = uuid_server.split('@', 1) if '@' in uuid_server else ('', uuid_server)
        server_port = server_port.split('#')[0]
        server, port_str = server_port.split(':', 1)
        port = int(re.sub(r'[^0-9]', '', port_str))

        if not (uuid and server and port):
            return None
        name = parts.split('#')[-1] if '#' in parts else f"vless-{url_filename}-{server}-{port}-{index}"

        config = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'udp': True,
            'tls': False,
            'network': 'tcp'
        }

        if rest:
            params = parse_qs(rest.split('#')[0])
            
            security = params.get('security', ['none'])[0].lower()
            if security == 'tls':
                config['tls'] = True
                config['sni'] = params.get('sni', [''])[0] or server
                if params.get('fp'):
                    config['fingerprint'] = params['fp'][0]
                if params.get('allowinsecure', ['0'])[0] == '1':
                    config['skip-cert-verify'] = True
            elif security == 'xtls':
                config['tls'] = True
                config['flow'] = params.get('flow', [''])[0]
                config['sni'] = params.get('sni', [''])[0] or server
                if params.get('fp'):
                    config['fingerprint'] = params['fp'][0]
                if params.get('allowinsecure', ['0'])[0] == '1':
                    config['skip-cert-verify'] = True
            
            network_type = params.get('type', ['tcp'])[0].lower()
            config['network'] = network_type

            if network_type == 'ws':
                config['ws-path'] = params.get('path', [''])[0]
                config['ws-headers'] = {'Host': params.get('host', [''])[0]}
                if params.get('maxearlydata', ['0'])[0] != '0':
                    config['ws-max-early-data'] = int(params['maxearlydata'][0])
                if params.get('earlydataheader', [''])[0]:
                    config['ws-early-data-header'] = params['earlydataheader'][0]
            
            elif network_type == 'grpc':
                config['grpc-service-name'] = params.get('servicename', [''])[0]
                config['grpc-auto-tuning'] = (params.get('grpc-auto-tuning', ['0'])[0] == '1')

        return config
    except Exception as e:
        print(f"解析 vless:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 解析 Trojan (trojan://) 链接
def parse_trojan_link(link, index, url_filename):
    try:
        if not link.startswith('trojan://'):
            return None
        parts = link.split('://', 1)[1]
        password_server_name, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        
        password_part = password_server_name.split('@')[0]
        password = password_part.split(':')[0]

        server_port_name_part = password_server_name.split('@', 1)[1] if '@' in password_server_name else password_server_name
        server_port_part = server_port_name_part.split('#')[0]
        server, port_str = server_port_part.split(':', 1)
        port = int(re.sub(r'[^0-9]', '', port_str))
        
        name = parts.split('#')[-1] if '#' in parts else f"trojan-{url_filename}-{server}-{port}-{index}"

        if not (password and server and port):
            return None
        
        config = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'udp': True,
            'tls': True
        }
        
        if rest:
            params = parse_qs(rest.split('#')[0])
            config['sni'] = params.get('sni', [''])[0] or server
            if params.get('alpn', [''])[0]:
                config['alpn'] = [apn.strip() for apn in params['alpn'][0].split(',')]
            if params.get('skip-cert-verify', ['0'])[0] == '1':
                config['skip-cert-verify'] = True
            if params.get('fingerprint', [''])[0]:
                config['fingerprint'] = params['fingerprint'][0]
            
            network_type = params.get('type', ['tcp'])[0].lower()
            config['network'] = network_type

            if network_type == 'ws':
                config['ws-path'] = params.get('path', [''])[0]
                config['ws-headers'] = {'Host': params.get('host', [''])[0]}
            
            elif network_type == 'grpc':
                config['grpc-service-name'] = params.get('servicename', [''])[0]
                config['grpc-auto-tuning'] = (params.get('grpc-auto-tuning', ['0'])[0] == '1')
        
        return config
    except Exception as e:
        print(f"解析 trojan:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 解析 Hysteria2 (hysteria2://) 链接
def parse_hysteria2_link(link, index, url_filename):
    try:
        if not link.startswith('hysteria2://'):
            return None
        parts = link.split('://', 1)[1]
        password_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        password, server_port = password_server.split('@', 1)
        server_port = server_port.split('#')[0]
        server, port_str = server_port.split(':', 1)
        port = int(re.sub(r'[^0-9]', '', port_str))
        if not (password and server and port):
            return None
        name = parts.split('#')[-1] if '#' in parts else f"hysteria2-{url_filename}-{server}-{port}-{index}"
        config = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'udp': True,
            'tls': True
        }
        if rest:
            params = parse_qs(rest.split('#')[0])
            config['sni'] = params.get('sni', [''])[0] or server
            if params.get('alpn', [''])[0]:
                config['alpn'] = [apn.strip() for apn in params['alpn'][0].split(',')]
            if params.get('insecure', ['0'])[0] == '1' or params.get('skip-cert-verify', ['0'])[0] == '1':
                config['skip-cert-verify'] = True
            config['obfs'] = params.get('obfs', [''])[0]
            config['obfs-password'] = params.get('obfs-password', [''])[0]
        return config
    except Exception as e:
        print(f"解析 hysteria2:// 链接失败 ({url_filename}): {e}, 链接: {link[:len(link)//2]}...")
        return None

# 尝试解析文本为字典（支持指定节点格式）
def parse_text_to_dict(text, url_filename):
    config = {'proxies': []}
    lines = text.splitlines()
    parsers = {
        'ss://': parse_ss_link,
        'ssr://': parse_ssr_link,
        'vmess://': parse_vmess_link,
        'vless://': parse_vless_link,
        'trojan://': parse_trojan_link,
        'hysteria2://': parse_hysteria2_link
    }
    for index, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for prefix, parser in parsers.items():
            if line.startswith(prefix):
                node = parser(line, index, url_filename)
                if node:
                    if 'tls' in node:
                        node['tls'] = bool(node['tls'])
                    config['proxies'].append(node)
                break
    return config if config['proxies'] else None

# 尝试解析文件内容 - 修正语法错误和逻辑
def parse_content(content, url_filename):
    content_preview = content[:100].replace('\n', ' ') + ('...' if len(content) > 100 else '')
    print(f"解析内容 ({url_filename}): {content_preview}")

    # 尝试作为 Base64 解码后的内容
    content_to_parse = content
    if is_valid_base64(content):
        print(f"检测到 {url_filename} 内容为 Base64 编码，尝试解码...")
        try:
            decoded_content = base64.urlsafe_b64decode(content.encode('utf-8') + b'==' * (-len(content) % 4)).decode('utf-8', errors='ignore')
            # 检查是否需要再次解码（如双重Base64）
            if is_valid_base64(decoded_content) and len(decoded_content) > 100:
                print(f"检测到 {url_filename} 解码后仍为 Base64 编码，再次解码...")
                decoded_content = base64.urlsafe_b64decode(decoded_content.encode('utf-8') + b'==' * (-len(decoded_content) % 4)).decode('utf-8', errors='ignore')
            content_to_parse = decoded_content
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"Base64 解码失败 ({url_filename}): {e}. 继续尝试原始内容解析。")
            # 如果解码失败，使用原始内容尝试后续解析

    # 首先尝试作为 YAML/JSON 解析
    try:
        config = yaml.safe_load(content_to_parse)
        
        if config and isinstance(config, dict):
            if 'proxies' in config and isinstance(config['proxies'], list):
                for index, proxy in enumerate(config['proxies']):
                    if not isinstance(proxy, dict):
                        print(f"警告: {url_filename} 中的代理列表包含非字典项，跳过: {proxy}")
                        continue

                    if 'name' not in proxy:
                        proxy['name'] = f"node-{url_filename}-{index}"
                    proxy.setdefault('udp', True)

                    if 'tls' in proxy:
                        if isinstance(proxy['tls'], str):
                            lower_tls = proxy['tls'].lower()
                            if lower_tls == 'true':
                                proxy['tls'] = True
                            elif lower_tls == 'false':
                                proxy['tls'] = False
                            else:
                                print(f"警告: 代理 '{proxy.get('name', '未知')}' 的 'tls' 字段是一个非布尔字符串 '{proxy['tls']}'。尝试转换为 False。")
                                proxy['tls'] = False
                        elif not isinstance(proxy['tls'], bool):
                            print(f"警告: 代理 '{proxy.get('name', '未知')}' 的 'tls' 字段类型异常 '{type(proxy['tls'])}'。尝试转换为布尔值。")
                            proxy['tls'] = bool(proxy['tls'])
                    
                    if 'port' in proxy and not isinstance(proxy['port'], int):
                        try:
                            proxy['port'] = int(str(proxy['port']))
                        except ValueError:
                            print(f"警告: 代理 '{proxy.get('name', '未知')}' 的 'port' 字段无法转换为整数: {proxy['port']}。")
                            del proxy['port']
                return config if config['proxies'] else None # 返回解析成功的代理配置
            elif isinstance(config, list) and all(isinstance(item, str) for item in config):
                 # 如果是列表且所有元素都是字符串，尝试作为链接列表解析
                return parse_text_to_dict(content_to_parse, url_filename)
        elif isinstance(config, list) and all(isinstance(item, str) for item in config):
            # 如果是列表且所有元素都是字符串，尝试作为链接列表解析
            return parse_text_to_dict(content_to_parse, url_filename)
            
    except yaml.YAMLError as e:
        print(f"YAML/JSON 解析失败 ({url_filename}): {e}. 尝试纯文本解析。")
        pass # 继续尝试纯文本解析

    # 如果 YAML/JSON 解析失败，或不是有效的代理配置，则尝试作为纯文本（链接列表）解析
    config_from_text = parse_text_to_dict(content_to_parse, url_filename)
    return config_from_text


# 处理单个 URL，提取代理并去重后保存
def process_url_and_save(url):
    parsed_url = urlparse(url)
    # 获取文件名，例如 'list.meta.yml' 或 'clash.yaml'
    original_filename = parsed_url.path.split('/')[-1]
    
    # 确保文件名是 .yaml 结尾，如果不是，就添加 .yaml
    if not original_filename.endswith(('.yaml', '.yml')):
        original_filename = original_filename.replace('.txt', '.yaml') # 常见的txt转yaml
        if not (original_filename.endswith(('.yaml', '.yml'))): # 如果替换后也不是，就直接加
            original_filename += '.yaml'

    output_directory = "sc"  # 定义输出目录为 "sc"
    os.makedirs(output_directory, exist_ok=True) # 创建 'sc' 目录如果它不存在

    output_filename_base = original_filename.rsplit('.', 1)[0] # 文件名（不含扩展名）
    output_extension = original_filename.rsplit('.', 1)[1] if '.' in original_filename else 'yaml'
    
    # 构建完整的文件路径，包括目录
    final_output_filename = os.path.join(output_directory, original_filename)
    counter = 1
    # 检查文件名是否存在，如果存在则添加序号
    while os.path.exists(final_output_filename):
        final_output_filename = os.path.join(output_directory, f"{output_filename_base}_{counter}.{output_extension}")
        counter += 1

    print(f"尝试获取 URL: {url}")
    try:
        response = session.get(url, timeout=20)
        response.raise_for_status()
        
        content = response.text
        
        # 解析内容，使用原始文件名作为标识
        config = parse_content(content, original_filename)
        
        if config and isinstance(config, dict) and config.get('proxies'):
            # 对当前文件内部的代理进行去重
            unique_proxies = []
            seen_fingerprints = set()
            for proxy in config['proxies']:
                if not isinstance(proxy, dict):
                    print(f"跳过 {original_filename} 中非字典代理项: {proxy}")
                    continue
                fingerprint = generate_node_fingerprint(proxy)
                if fingerprint not in seen_fingerprints:
                    unique_proxies.append(proxy)
                    seen_fingerprints.add(fingerprint)
                else:
                    print(f"发现 {original_filename} 中重复代理，已跳过: {proxy.get('name', '未知名称')} ({proxy.get('server')}:{proxy.get('port')})")
            
            print(f"从 {original_filename} 提取 {len(config['proxies'])} 个代理，去重后 {len(unique_proxies)} 个。")
            
            # 填充 Clash 配置模板
            final_clash_config = clash_config_template.copy()
            final_clash_config['proxies'] = unique_proxies

            # 更新代理组
            proxy_names = [proxy['name'] for proxy in unique_proxies]
            
            final_clash_config['proxy-groups'] = [
                {
                    "name": "节点选择",
                    "type": "select",
                    "proxies": [
                        "自动选择",
                        "故障转移",
                        "DIRECT",
                        "手动选择"
                    ]
                },
                {
                    "name": "自动选择",
                    "type": "url-test",
                    "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
                    "proxies": [],
                    "url": "http://www.pinterest.com",
                    "interval": 300,
                    "tolerance": 50
                },
                {
                    "name": "故障转移",
                    "type": "fallback",
                    "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
                    "proxies": [],
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": 300
                },
                {
                    "name": "手动选择",
                    "type": "select",
                    "proxies": []
                },
            ]

            for group in final_clash_config['proxy-groups']:
                if group['name'] in ['自动选择', '故障转移', '手动选择']:
                    filtered_names = [name for name in proxy_names if not re.search(r'(?i)中国|China|CN|电信|移动|联通', name)]
                    group['proxies'] = []
                    group['proxies'].extend(filtered_names)
                    group['proxies'].insert(0, 'DIRECT')
                elif group['name'] == '节点选择':
                    default_proxies = ["自动选择", "故障转移", "DIRECT", "手动选择"]
                    group['proxies'] = [p for p in default_proxies if p in [g['name'] for g in final_clash_config['proxy-groups']]]

            for group in final_clash_config['proxy-groups']:
                if not group['proxies']:
                    if group['type'] == 'select' and group['name'] != '节点选择':
                        group['proxies'] = ['DIRECT']
                    elif group['type'] != 'select':
                        group['proxies'].append('DIRECT')
                
                if 'DIRECT' in group['proxies'] and group['proxies'].count('DIRECT') > 1:
                    group['proxies'] = [p for p in group['proxies'] if p != 'DIRECT']
                    group['proxies'].insert(0, 'DIRECT')


            # 保存到文件
            print(f"保存配置到 {final_output_filename}...")
            with open(final_output_filename, 'w', encoding='utf-8') as f:
                yaml.dump(final_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False,
                           indent=2, width=80)
            print(f"文件 {final_output_filename} 已生成，包含 {len(unique_proxies)} 个去重后的节点。")
        else:
            print(f"从 {url} 未能提取到有效代理，不生成文件。")

    except requests.RequestException as e:
        print(f"无法获取或解析 {url}: {e}")
    except Exception as e:
        print(f"处理 {url} 时发生未知错误: {e}")

# 主函数
def main():
    print("开始获取并按来源保存每个订阅链接的配置...")
    for url in urls:
        process_url_and_save(url)
    print("所有订阅链接处理完成。")

if __name__ == "__main__":
    main()
