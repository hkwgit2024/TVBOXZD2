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
    
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
 
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

# 解析 Shadowsocks (ss://) 链接
def parse_ss_link(link, index, url):
    try:
        if link.startswith('ss://'):
            # 解码 Base64 部分（去除 ss:// 前缀）
            encoded = link[5:].split('#')[0].split('@')[0]
            decoded = base64.urlsafe_b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
            # 提取加密方法和密码
            method, password = decoded.split(':')
            # 提取服务器和端口
            server_port = link[5:].split('@')[1].split('#')[0]
            server, port = server_port.split(':')
            # 获取节点名称（从 # 后的备注或生成默认名称）
            filename = urlparse(url).path.split('/')[-1] or 'unknown'
            name = link.split('#')[-1] if '#' in link else f"ss-{filename}-{server}-{port}-{index}"
            return {
                'name': name,
                'type': 'ss',
                'server': server,
                'port': int(port),
                'cipher': method,
                'password': password,
                'udp': True  # mihomo 默认支持 UDP
            }
    except Exception as e:
        print(f"解析 ss:// 链接失败 ({url}): {e}")
        return None

# 解析 Vmess (vmess://) 链接
def parse_vmess_link(link, index, url):
    try:
        if link.startswith('vmess://'):
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
                'udp': True  # mihomo 默认支持 UDP
            }
    except Exception as e:
        print(f"解析 vmess:// 链接失败 ({url}): {e}")
        return None

# 解析 VLESS (vless://) 链接
def parse_vless_link(link, index, url):
    try:
        if link.startswith('vless://'):
            # 格式：vless://uuid@server:port?param1=value1&param2=value2#remark
            parts = link.split('://', 1)[1]
            uuid_server, rest = parts.split('?', 1) if '?' in parts else (parts, '')
            uuid, server_port = uuid_server.split('@', 1)
            server, port = server_port.split('#')[0].split(':')
            # 解析查询参数
            params = parse_qs(rest) if rest else {}
            filename = urlparse(url).path.split('/')[-1] or 'unknown'
            name = parts.split('#')[-1] if '#' in parts else f"vless-{filename}-{server}-{port}-{index}"
            config = {
                'name': name,
                'type': 'vless',
                'server': server,
                'port': int(port),
                'uuid': uuid,
                'udp': True,  # mihomo 默认支持 UDP
                'tls': params.get('security', ['none'])[0] == 'tls',
                'network': params.get('type', ['tcp'])[0],
            }
            # 添加 WebSocket 或其他网络参数
            if config['network'] == 'ws':
                config['ws-opts'] = {
                    'path': params.get('path', [''])[0],
                    'headers': {'Host': params.get('host', [''])[0]}
                }
            return config
    except Exception as e:
        print(f"解析 vless:// 链接失败 ({url}): {e}")
        return None

# 检查是否为有效的 Base64 字符串
def is_valid_base64(s):
    return bool(re.match(r'^[A-Za-z0-9+/=]+$', s))

# 尝试解析文本为字典（支持键值对、ss://、vmess:// 和 vless:// 链接）
def parse_text_to_dict(text, url):
    config = {'proxies': []}
    lines = text.splitlines()
    current_section = None
    for index, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # 处理 ss:// 链接
        if line.startswith('ss://'):
            node = parse_ss_link(line, index, url)
            if node:
                config['proxies'].append(node)
            continue
        # 处理 vmess:// 链接
        if line.startswith('vmess://'):
            node = parse_vmess_link(line, index, url)
            if node:
                config['proxies'].append(node)
            continue
        # 处理 vless:// 链接
        if line.startswith('vless://'):
            node = parse_vless_link(line, index, url)
            if node:
                config['proxies'].append(node)
            continue
        # 简单键值对解析（假设格式为 key: value 或 key=value）
        if ':' in line or '=' in line:
            separator = ':' if ':' in line else '='
            key, value = map(str.strip, line.split(separator, 1))
            if key and value:
                try:
                    if value.lower() in ('true', 'false'):
                        value = value.lower() == 'true'
                    elif value.isdigit():
                        value = int(value)
                    elif value.replace('.', '', 1).isdigit():
                        value = float(value)
                    elif value.startswith('[') and value.endswith(']'):
                        value = json.loads(value)
                except:
                    pass
                if current_section:
                    config[current_section][key] = value
                else:
                    config[key] = value
        # 处理嵌套结构的开始（例如 dns:）
        elif line.endswith(':'):
            current_section = line[:-1]
            config[current_section] = {}
    return config

# 尝试解析文件内容
def parse_content(content, url):
    # 记录内容片段以便调试（最多 100 字符）
    content_preview = content[:100].replace('\n', ' ') + ('...' if len(content) > 100 else '')
    print(f"解析内容 ({url}): {content_preview}")

    # 尝试作为 YAML 解析
    try:
        config = yaml.safe_load(content)
        if config and isinstance(config, dict):
            # 确保节点在 proxies 键下
            if 'proxies' in config and isinstance(config['proxies'], list):
                for index, proxy in enumerate(config['proxies']):
                    if not isinstance(proxy, dict):
                        print(f"无效代理配置 ({url}): {proxy}")
                        continue
                    if 'name' not in proxy:
                        filename = urlparse(url).path.split('/')[-1] or 'unknown'
                        proxy['name'] = f"node-{filename}-{index}"
                    proxy.setdefault('udp', True)  # mihomo 默认支持 UDP
            return config
    except yaml.YAMLError as e:
        print(f"YAML 解析失败 ({url}): {e}")

    # 尝试作为 Base64 解码后解析为 JSON
    if is_valid_base64(content.strip()):
        try:
            decoded = base64.urlsafe_b64decode(content + '==' * (-len(content) % 4)).decode('utf-8', errors='ignore')
            config = json.loads(decoded)
            if config and isinstance(config, dict):
                # 确保节点有 name 字段
                if isinstance(config, list):
                    config = {'proxies': config}
                if 'proxies' in config and isinstance(config['proxies'], list):
                    for index, proxy in enumerate(config['proxies']):
                        if not isinstance(proxy, dict):
                            print(f"无效代理配置 ({url}): {proxy}")
                            continue
                        if 'name' not in proxy:
                            filename = urlparse(url).path.split('/')[-1] or 'unknown'
                            proxy['name'] = f"node-{filename}-{index}"
                        proxy.setdefault('udp', True)  # mihomo 默认支持 UDP
                return config
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"Base64/JSON 解析失败 ({url}): {e}")

    # 尝试作为纯文本解析
    try:
        config = parse_text_to_dict(content, url)
        if config and isinstance(config, dict):
            return config
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
            # 尝试解码为 UTF-8，忽略非 ASCII 错误
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
            print(f"跳过无效配置: {config}")
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
    # 确保每个代理有唯一的 name
    seen_names = set()
    merged['proxies'] = [proxy for proxy in merged['proxies'] if isinstance(proxy, dict)]
    for index, proxy in enumerate(merged['proxies']):
        if 'name' not in proxy:
            proxy['name'] = f"node-{index}"
        if proxy['name'] in seen_names:
            proxy['name'] = f"{proxy['name']}-{index}"
        seen_names.add(proxy['name'])
        proxy.setdefault('udp', True)  # mihomo 默认支持 UDP
    # 更新 proxy-groups 中的 proxies 列表
    proxy_names = [proxy['name'] for proxy in merged['proxies']]
    for group in merged['proxy-groups']:
        if group['name'] in ['自动选择', '故障转移', '手动选择']:
            group['proxies'].extend([name for name in proxy_names if not any(exclude in name.lower() for exclude in ['中国', 'china', 'cn', '电信', '移动', '联通'])])
    return merged

# 主函数
def main():
    # 创建 input 目录
    os.makedirs('input', exist_ok=True)

    # 获取并解析所有配置
    configs = fetch_and_parse_configs(urls)

    if not configs or not any(config.get('proxies', []) for config in configs if isinstance(config, dict)):
        print("错误：无法解析任何有效节点，输出文件将包含基础配置")
        merged_config = clash_config_template.copy()
        yaml_output = "# 错误：无法解析任何有效节点，仅包含基础配置\n" + yaml.dump(merged_config, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open('input/output.yml', 'w', encoding='utf-8') as f:
            f.write(yaml_output)
        print("配置已保存到 input/output.yml（仅基础配置）")
        print("\n合并后的 YAML 内容：")
        print(yaml_output)
        return

    # 合并配置
    merged_config = merge_configs(configs)

    # 转换为 YAML
    yaml_output = yaml.dump(merged_config, allow_unicode=True, sort_keys=False, default_flow_style=False)

    # 保存到 input/output.yml
    with open('input/output.yml', 'w', encoding='utf-8') as f:
        f.write(yaml_output)

    print("配置已合并并保存到 input/output.yml")
    print("\n合并后的 YAML 内容：")
    print(yaml_output)

if __name__ == "__main__":
    main()
