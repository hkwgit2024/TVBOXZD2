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

# Clash/Mihomo 配置模板（精简，仅保留必要字段）
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "dns": {
        "enable": True,
        "ipv6": False,
        "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    },
    "proxies": [],
    "proxy-groups": [
        {"name": "节点选择", "type": "select", "proxies": ["自动选择", "故障转移", "DIRECT", "手动选择"]},
        {"name": "自动选择", "type": "url-test", "exclude-filter": "(?i)中国|China|CN|电信|移动|联通", "proxies": [], "url": "http://www.pinterest.com", "interval": 300, "tolerance": 50},
        {"name": "故障转移", "type": "fallback", "exclude-filter": "(?i)中国|China|CN|电信|移动|联通", "proxies": [], "url": "http://www.gstatic.com/generate_204", "interval": 300},
        {"name": "手动选择", "type": "select", "proxies": []}
    ],
    "rules": ["DOMAIN,app.adjust.com,DIRECT", "DOMAIN-SUFFIX,google.com,DIRECT"]
}

# 配置请求重试机制
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))

# 解析 Shadowsocks (ss://) 链接
def parse_ss_link(link, index, url):
    try:
        if not link.startswith('ss://'):
            return None
        parts = link.split('://', 1)[1]
        encoded = parts.split('#')[0].split('@')[0] if '@' in parts else parts.split('?')[0]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        method, password = decoded.rsplit(':', 1)
        server_port = parts.split('@')[1].split('#')[0].split('?')[0] if '@' in parts else parts
        server, port = server_port.rsplit(':', 1)
        port = re.sub(r'[^0-9]', '', port)  # 清理端口
        if not port.isdigit():
            raise ValueError(f"无效端口: {port}")
        filename = urlparse(url).path.split('/')[-1] or 'unknown'
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
        print(f"解析 ss:// 失败 ({url}): {e}, 链接: {link[:50]}...")
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
        server, port = server_port.rsplit(':', 1)
        port = re.sub(r'[^0-9]', '', port)  # 清理端口
        if not port.isdigit():
            raise ValueError(f"无效端口: {port}")
        filename = urlparse(url).path.split('/')[-1] or 'unknown'
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
        print(f"解析 vless:// 失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 解析 Vmess (vmess://) 链接
def parse_vmess_link(link, index, url):
    try:
        if not link.startswith('vmess://'):
            return None
        encoded = link[8:]
        decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        config = json.loads(decoded)
        filename = urlparse(url).path.split('/')[-1] or 'unknown'
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
        print(f"解析 vmess:// 失败 ({url}): {e}, 链接: {link[:50]}...")
        return None

# 检查是否为有效的 Base64 字符串
def is_valid_base64(s):
    return bool(re.match(r'^[A-Za-z0-9+/=]+$', s.strip()))

# 尝试解析文本为字典
def parse_text_to_dict(text, url):
    config = {'proxies': []}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for parse_func in [parse_ss_link, parse_vmess_link, parse_vless_link]:
            node = parse_func(line, index, url)
            if node:
                config['proxies'].append(node)
                break
    return config

# 尝试解析文件内容
def parse_content(content, url):
    content_preview = content[:100].replace('\n', ' ') + ('...' if len(content) > 100 else '')
    print(f"解析内容 ({url}): {content_preview}")

    # 尝试 YAML
    try:
        config = yaml.safe_load(content)
        if config and isinstance(config, dict):
            if 'proxies' in config and isinstance(config['proxies'], list):
                for index, proxy in enumerate(config['proxies']):
                    if not isinstance(proxy, dict):
                        continue
                    if 'name' not in proxy:
                        filename = urlparse(url).path.split('/')[-1] or 'unknown'
                        proxy['name'] = f"node-{filename}-{index}"
                    proxy.setdefault('udp', True)
            return config
    except yaml.YAMLError as e:
        print(f"YAML 解析失败 ({url}): {e}")

    # 尝试 Base64
    if is_valid_base64(content):
        try:
            decoded = base64.urlsafe_b64decode(content + '==' * (-len(content) % 4)).decode('utf-8', errors='ignore')
            config = json.loads(decoded)
            if config and isinstance(config, dict):
                if isinstance(config, list):
                    config = {'proxies': config}
                if 'proxies' in config and isinstance(config['proxies'], list):
                    for index, proxy in enumerate(config['proxies']):
                        if not isinstance(proxy, dict):
                            continue
                        if 'name' not in proxy:
                            filename = urlparse(url).path.split('/')[-1] or 'unknown'
                            proxy['name'] = f"node-{filename}-{index}"
                        proxy.setdefault('udp', True)
                return config
        except (base64.binascii.Error, json.JSONDecodeError) as e:
            print(f"Base64/JSON 解析失败 ({url}): {e}")

    # 尝试文本
    try:
        return parse_text_to_dict(content, url)
    except Exception as e:
        print(f"文本解析失败 ({url}): {e}")

    print(f"无法解析来自 {url} 的内容")
    return None

# 获取并解析所有链接的配置
def fetch_and_parse_configs(urls):
    all_configs = []
    for url in urls:
        try:
            response = session.get(url, timeout=10)
            response.raise_for_status()
            content = response.text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
            config = parse_content(content, url)
            if config and isinstance(config, dict):
                all_configs.append(config)
                print(f"成功解析 {url}")
            else:
                print(f"跳过无效配置 ({url})")
        except requests.RequestException as e:
            print(f"无法获取 {url}: {e}")
    return all_configs

# 合并配置
def merge_configs(configs):
    merged = clash_config_template.copy()
    for config in configs:
        if not isinstance(config, dict):
            continue
        for key, value in config.items():
            if key == 'proxies' and isinstance(value, list):
                merged['proxies'].extend([proxy for proxy in value if isinstance(proxy, dict)])
            elif key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key].update(value)
            elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
                merged[key].extend(value)
            else:
                merged[key] = value
    seen_names = set()
    merged['proxies'] = [proxy for proxy in merged['proxies'] if isinstance(proxy, dict)]
    for index, proxy in enumerate(merged['proxies']):
        if 'name' not in proxy:
            proxy['name'] = f"node-{index}"
        if proxy['name'] in seen_names:
            proxy['name'] = f"{proxy['name']}-{index}"
        seen_names.add(proxy['name'])
        proxy.setdefault('udp', True)
    proxy_names = [proxy['name'] for proxy in merged['proxies']]
    for group in merged['proxy-groups']:
        if group['name'] in ['自动选择', '故障转移', '手动选择']:
            group['proxies'].extend([name for name in proxy_names if not any(exclude in name.lower() for exclude in ['中国', 'china', 'cn', '电信', '移动', '联通'])])
    return merged

# 主函数
def main():
    os.makedirs('input', exist_ok=True)
    configs = fetch_and_parse_configs(urls)
    if not configs or not any(config.get('proxies', []) for config in configs if isinstance(config, dict)):
        print("错误：无法解析任何有效节点")
        merged_config = clash_config_template.copy()
        yaml_output = "# 错误：无法解析任何有效节点，仅包含基础配置\n" + yaml.dump(merged_config, allow_unicode=True, sort_keys=False)
        with open('input/output.yml', 'w', encoding='utf-8') as f:
            f.write(yaml_output)
        print("已保存基础配置到 input/output.yml")
        return
    merged_config = merge_configs(configs)
    yaml_output = "# 合并后的配置\n" + yaml.dump(merged_config, allow_unicode=True, sort_keys=False)
    with open('input/output.yml', 'w', encoding='utf-8') as f:
        f.write(yaml_output)
    print("配置已保存到 input/output.yml")
    print("\n合并后的 YAML 内容：")
    print(yaml_output)

if __name__ == "__main__":
    main()
