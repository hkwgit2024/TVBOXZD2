#取消合并配置
import requests
import base64
import json
import yaml
import os
import re
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# GitHub raw 链接列表
urls = [
    "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
]

# Clash/Mihomo 配置模板
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
    "proxies": [],
    "proxy-groups": [
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
    ],
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
    return bool(re.match(r'^[A-Za-z0-9+/=]+$', s.strip()))

# 解析 Shadowsocks (ss://) 链接
def parse_ss_link(link, index, url):
    try:
        if not link.startswith('ss://'):
            return None
        parts = link.split('://', 1)[1]
        encoded = parts.split('#')[0].split('@')[0] if '@' in parts else parts.split('?')[0]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        method, password = decoded.rsplit(':', 1)
        server_port = parts.split('@')[1].split('#')[0].split('?')[0] if '@' in parts else parts.split('?')[1]
        server, port = server_port.split(':')
        port = re.sub(r'[^0-9]', '', port)
        if not (method and password and server and port):
            return None
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = parts.split('#')[-1] if '#' in parts else f"ss-{filename}-{server}-{port}-{index}"
        config = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }
        if '?' in parts:
            params = parse_qs(parts.split('?')[1].split('#')[0])
            if params.get('type', [''])[0] == 'ws':
                config['network'] = 'ws'
                config['ws-opts'] = {
                    'path': params.get('path', [''])[0],
                    'headers': {'Host': params.get('sni', [''])[0] or params.get('host', [''])[0]}
                }
                config['tls'] = params.get('security', ['none'])[0] == 'tls'
        return config
    except Exception as e:
        print(f"解析 ss:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 ShadowsocksR (ssr://) 链接
def parse_ssr_link(link, index, url):
    try:
        if not link.startswith('ssr://'):
            return None
        encoded = link[6:].split('#')[0]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        parts = decoded.split(':')
        if len(parts) < 6:
            return None
        server, port, protocol, method, obfs, password = parts[:6]
        password = base64.urlsafe_b64decode(password + '==' * (-len(password) % 4)).decode('utf-8', errors='ignore')
        params = parse_qs(parts[6].lstrip('/?')) if len(parts) > 6 else {}
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = params.get('remarks', [f"ssr-{filename}-{server}-{port}-{index}"])[0]
        config = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': int(port),
            'cipher': method,
            'obfs': obfs,
            'protocol': protocol,
            'password': password,
            'udp': True
        }
        if params.get('obfsparam', [''])[0]:
            config['obfs-param'] = base64.urlsafe_b64decode(params.get('obfsparam', [''])[0] + '==' * (-len(params.get('obfsparam', [''])[0]) % 4)).decode('utf-8', errors='ignore')
        if params.get('protoparam', [''])[0]:
            config['protocol-param'] = base64.urlsafe_b64decode(params.get('protoparam', [''])[0] + '==' * (-len(params.get('protoparam', [''])[0]) % 4)).decode('utf-8', errors='ignore')
        return config
    except Exception as e:
        print(f"解析 ssr:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 Vmess (vmess://) 链接
def parse_vmess_link(link, index, url):
    try:
        if not link.startswith('vmess://'):
            return None
        encoded = link[8:]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        config = json.loads(decoded)
        if not (config.get('add') and config.get('port') and config.get('id')):
            return None
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = config.get('ps', f"vmess-{filename}-{index}")
        return {
            'name': name,
            'type': 'vmess',
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'network': config.get('net', 'tcp'),
            'tls': config.get('tls') == 'tls',
            'ws-path': config.get('path', ''),
            'ws-headers': {'Host': config.get('host', '')},
            'udp': True
        }
    except Exception as e:
        print(f"解析 vmess:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 VLESS (vless://) 链接
def parse_vless_link(link, index, url):
    try:
        if not link.startswith('vless://'):
            return None
        parts = link.split('://', 1)[1]
        uuid_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        uuid, server_port = uuid_server.split('@', 1) if '@' in uuid_server else ('', uuid_server)
        server_port = server_port.split('#')[0]
        server, port = server_port.split(':', 1)
        port = re.sub(r'[^0-9]', '', port)
        if not (uuid and server and port):
            return None
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = parts.split('#')[-1] if '#' in parts else f"vless-{filename}-{server}-{port}-{index}"
        config = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'udp': True,
            'tls': False,
            'network': 'tcp'
        }
        if rest:
            params = parse_qs(rest.split('#')[0])
            config['tls'] = params.get('security', ['none'])[0] == 'tls'
            config['network'] = params.get('type', ['tcp'])[0]
            if config['network'] == 'ws':
                config['ws-opts'] = {
                    'path': params.get('path', [''])[0],
                    'headers': {'Host': params.get('sni', [''])[0] or params.get('host', [''])[0]}
                }
        return config
    except Exception as e:
        print(f"解析 vless:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 Trojan (trojan://) 链接
def parse_trojan_link(link, index, url):
    try:
        if not link.startswith('trojan://'):
            return None
        parts = link.split('://', 1)[1]
        password_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        password, server_port = password_server.split('@', 1)
        server_port = server_port.split('#')[0]
        server, port = server_port.split(':', 1)
        port = re.sub(r'[^0-9]', '', port)
        if not (password and server and port):
            return None
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = parts.split('#')[-1] if '#' in parts else f"trojan-{filename}-{server}-{port}-{index}"
        config = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True
        }
        if rest:
            params = parse_qs(rest.split('#')[0])
            config['sni'] = params.get('sni', [''])[0] or server
            config['tls'] = True
            if params.get('type', [''])[0] == 'ws':
                config['network'] = 'ws'
                config['ws-opts'] = {
                    'path': params.get('path', [''])[0],
                    'headers': {'Host': params.get('sni', [''])[0] or params.get('host', [''])[0]}
                }
        return config
    except Exception as e:
        print(f"解析 trojan:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 Hysteria2 (hysteria2://) 链接
def parse_hysteria2_link(link, index, url):
    try:
        if not link.startswith('hysteria2://'):
            return None
        parts = link.split('://', 1)[1]
        password_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
        password, server_port = password_server.split('@', 1)
        server_port = server_port.split('#')[0]
        server, port = server_port.split(':', 1)
        port = re.sub(r'[^0-9]', '', port)
        if not (password and server and port):
            return None
        filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
        name = parts.split('#')[-1] if '#' in parts else f"hysteria2-{filename}-{server}-{port}-{index}"
        config = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True,
            'tls': True
        }
        if rest:
            params = parse_qs(rest.split('#')[0])
            config['sni'] = params.get('sni', [''])[0] or server
            config['obfs'] = params.get('obfs', [''])[0]
            config['obfs-password'] = params.get('obfs-password', [''])[0]
        return config
    except Exception as e:
        print(f"解析 hysteria2:// 链接失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 尝试解析文本为字典（支持指定节点格式）
def parse_text_to_dict(text, url):
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
                node = parser(line, index, url)
                if node:
                    config['proxies'].append(node)
                break
    return config if config['proxies'] else None

# 尝试解析文件内容
def parse_content(content, url):
    content_preview = content[:100].replace('\n', ' ') + ('...' if len(content) > 100 else '')
    print(f"解析内容 ({url}): {content_preview}")

    # 尝试作为 YAML 解析
    try:
        config = yaml.safe_load(content)
        if config and isinstance(config, dict) and 'proxies' in config and isinstance(config['proxies'], list):
            filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
            for index, proxy in enumerate(config['proxies']):
                if not isinstance(proxy, dict):
                    continue
                if 'name' not in proxy:
                    proxy['name'] = f"node-{filename}-{index}"
                proxy.setdefault('udp', True)
            return config if config['proxies'] else None
    except yaml.YAMLError as e:
        print(f"YAML 解析失败 ({url}): {e}")

    # 尝试作为 Base64 解码后解析为 JSON
    if is_valid_base64(content):
        try:
            decoded = base64.urlsafe_b64decode(content + '==' * (-len(content) % 4)).decode('utf-8', errors='ignore')
            config = json.loads(decoded)
            if config and isinstance(config, dict):
                if isinstance(config, list):
                    config = {'proxies': config}
                if 'proxies' in config and isinstance(config['proxies'], list):
                    filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
                    for index, proxy in enumerate(config['proxies']):
                        if not isinstance(proxy, dict):
                            continue
                        if 'name' not in proxy:
                            proxy['name'] = f"node-{filename}-{index}"
                        proxy.setdefault('udp', True)
                    return config if config['proxies'] else None
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Base64/JSON 解析失败 ({url}): {e}")

    # 尝试作为纯文本解析
    config = parse_text_to_dict(content, url)
    return config

# 保存单个配置到文件
def save_config(config, url):
    filename = urlparse(url).path.split('/')[-1].replace('.txt', '.yml')
    output_path = os.path.join('input', filename)
    merged_config = clash_config_template.copy()
    if config and isinstance(config, dict) and 'proxies' in config:
        merged_config['proxies'] = config['proxies']
        proxy_names = [proxy['name'] for proxy in config['proxies']]
        for group in merged_config['proxy-groups']:
            if group['name'] in ['自动选择', '故障转移', '手动选择']:
                group['proxies'].extend([name for name in proxy_names if not any(exclude in name.lower() for exclude in ['中国', 'china', 'cn', '电信', '移动', '联通'])])
    yaml_output = f"# 配置来自 {url}\n" + yaml.dump(merged_config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(yaml_output)
    print(f"配置已保存到 {output_path}")

# 获取并解析所有链接的配置
def fetch_and_parse_configs(urls):
    os.makedirs('input', exist_ok=True)
    for url in urls:
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            content = response.text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
            config = parse_content(content, url)
            if config and isinstance(config, dict) and config.get('proxies'):
                save_config(config, url)
                print(f"成功解析 {url}")
            else:
                print(f"跳过无效配置 ({url})：无有效节点")
        except requests.RequestException as e:
            print(f"无法获取 {url}: {e}")

# 主函数
def main():
    fetch_and_parse_configs(urls)

if __name__ == "__main__":
    main()
