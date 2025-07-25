import requests
import base64
import json
import yaml
import os
import re
import sys # 导入 sys 模块
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
    "external-controller": "0.0.0.0:9090",
    "secret": "",
    "dns": {
        "enable": True,
        "listen": "0.0.0.0:53",
        "ipv6": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.media.microsoft.com",
            "*.msftconnecttest.com",
            "*.msftncsi.com",
            "*.srv.nintendo.net",
            "*.stun.playstation.net",
            "xbox.*.microsoft.com",
            "*.xboxlive.com",
            "assets.xboxlive.com",
            "stun.xboxlive.com",
            "*.msedge.net",
            "cdn.msedge.net",
            "www.msftconnecttest.com",
            "www.msftncsi.com",
            "api.msftcontent.com",
            "api.onedrive.com",
            "msftconnecttest.com",
            "msftncsi.com"
        ],
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29",
            "1.2.4.8"
        ],
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        "fallback": [
            "tls://8.8.4.4:853",
            "tls://1.0.0.1:853",
            "https://doh.dns.sb/dns-query",
            "tcp://1.1.1.1:53"
        ],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "CN",
            "ipcidr": [
                "240.0.0.0/4"
            ]
        }
    },
    "proxy-groups": [
        {"name": "节点选择", "type": "select", "proxies": []},
        {"name": "国内网站", "type": "direct", "proxies": ["DIRECT"]},
        {"name": "国外网站", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "TikTok", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "YouTube", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "Netflix", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "Pornhub", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "Spotify", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "Telegram", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "百度", "type": "select", "proxies": ["DIRECT", "节点选择"]},
        {"name": "谷歌", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "微软", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "苹果", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "游戏", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "OpenAI", "type": "select", "proxies": ["节点选择", "DIRECT"]},
        {"name": "Github", "type": "select", "proxies": ["节点选择", "DIRECT"]}
    ],
    "rules": [
        "PROCESS-NAME,Quantumult X,DIRECT",
        "PROCESS-NAME,Surge,DIRECT",
        "PROCESS-NAME,ClashX,DIRECT",
        "PROCESS-NAME,Shadowrocket,DIRECT",
        "DOMAIN-SUFFIX,google.com,谷歌",
        "DOMAIN-SUFFIX,youtube.com,YouTube",
        "DOMAIN-SUFFIX,netflix.com,Netflix",
        "DOMAIN-SUFFIX,tiktok.com,TikTok",
        "DOMAIN-SUFFIX,spotify.com,Spotify",
        "DOMAIN-SUFFIX,github.com,Github",
        "DOMAIN-SUFFIX,openai.com,OpenAI",
        "DOMAIN-SUFFIX,bing.com,微软",
        "DOMAIN-SUFFIX,microsoft.com,微软",
        "DOMAIN-SUFFIX,apple.com,苹果",
        "DOMAIN-SUFFIX,icloud.com,苹果",
        "DOMAIN-SUFFIX,live.com,微软",
        "DOMAIN-SUFFIX,xvideos.com,Pornhub",
        "DOMAIN-SUFFIX,pornhub.com,Pornhub",
        "DOMAIN-SUFFIX,xnxx.com,Pornhub",
        "DOMAIN-SUFFIX,xhamster.com,Pornhub",
        "DOMAIN-SUFFIX,twitter.com,国外网站",
        "DOMAIN-SUFFIX,facebook.com,国外网站",
        "DOMAIN-SUFFIX,instagram.com,国外网站",
        "DOMAIN-SUFFIX,telegram.org,Telegram",
        "DOMAIN-SUFFIX,douyin.com,国内网站",
        "DOMAIN-SUFFIX,weibo.com,国内网站",
        "DOMAIN-SUFFIX,qq.com,国内网站",
        "DOMAIN-SUFFIX,baidu.com,百度",
        "DOMAIN-SUFFIX,bilibili.com,国内网站",
        "DOMAIN-SUFFIX,taobao.com,国内网站",
        "DOMAIN-SUFFIX,jd.com,国内网站",
        "GEOSITE,CN,国内网站",
        "GEOIP,CN,国内网站",
        "MATCH,国外网站"
    ]
}

# 预设的代理组，用于匹配规则中的分组
default_proxy_groups = [
    "节点选择", "国内网站", "国外网站", "TikTok", "YouTube", "Netflix",
    "Pornhub", "Spotify", "Telegram", "百度", "谷歌", "微软", "苹果",
    "游戏", "OpenAI", "Github", "DIRECT" # DIRECT 也是一个可选项
]

def parse_vmess(vmess_link):
    try:
        if not vmess_link.startswith("vmess://"):
            return None
        encoded_str = vmess_link[8:]
        decoded_str = base64.b64decode(encoded_str).decode('utf-8')
        vmess_data = json.loads(decoded_str)

        name = vmess_data.get('ps', 'Unnamed-VMess')
        server = vmess_data.get('add')
        port = vmess_data.get('port')
        uuid = vmess_data.get('id')
        alterId = vmess_data.get('aid', 0)
        cipher = vmess_data.get('scy', 'auto') # scy for security, fallback to auto
        network = vmess_data.get('net', 'tcp')
        tls = vmess_data.get('tls', '') == 'tls'
        udp = True # Default UDP to true as per common Clash configs

        clash_proxy = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": alterId,
            "cipher": cipher,
            "udp": udp
        }

        if network == 'ws':
            clash_proxy["network"] = "ws"
            clash_proxy["ws-path"] = vmess_data.get('path', '/')
            clash_proxy["ws-headers"] = {"Host": vmess_data.get('host', server)}
            if tls:
                clash_proxy["tls"] = True
                clash_proxy["servername"] = vmess_data.get('host', server) # sni
                clash_proxy["skip-cert-verify"] = False # Default

        # Add other network types if needed (e.g., http, grpc, h2)
        elif network == 'tcp' and tls:
            clash_proxy["tls"] = True
            clash_proxy["servername"] = vmess_data.get('host', server) # sni

        return clash_proxy
    except Exception as e:
        # print(f"Error parsing VMess link {vmess_link}: {e}")
        return None

def parse_vless(vless_link):
    try:
        if not vless_link.startswith("vless://"):
            return None
        
        # Split the link into userinfo and hostinfo parts
        # vless://uuid@server:port?params#name
        parts = vless_link[8:].split('@', 1)
        if len(parts) != 2:
            return None # Invalid format

        uuid = parts[0]
        
        server_info_name_parts = parts[1].split('#', 1)
        server_info_params_parts = server_info_name_parts[0].split('?', 1)

        server_port_str = server_info_params_parts[0]
        server, port_str = server_port_str.split(':', 1)
        port = int(port_str)

        params = {}
        if len(server_info_params_parts) == 2:
            query_string = server_info_params_parts[1]
            params = parse_qs(query_string)
            # Flatten lists to single values for parameters
            params = {k: v[0] for k, v in params.items()}

        name = ""
        if len(server_info_name_parts) == 2:
            name = server_info_name_parts[1]
            # Decode URL-encoded characters in the name
            name = requests.utils.unquote(name)
        
        # Default name if not provided in the link
        if not name:
            name = f"Unnamed-VLESS-{server}:{port}"

        network = params.get('type', 'tcp')
        tls = params.get('security', '') == 'tls'
        sni = params.get('sni', server)
        fp = params.get('fp', '') # fingerprint
        pbk = params.get('pbk', '') # public key
        flow = params.get('flow', '')
        udp = True # Default UDP to true as per common Clash configs

        clash_proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": udp
        }

        if tls:
            clash_proxy["tls"] = True
            if sni:
                clash_proxy["servername"] = sni # sni
            if fp:
                clash_proxy["fingerprint"] = fp
            if pbk:
                clash_proxy["publicKey"] = pbk
        
        if flow: # Add flow if present (e.g., for reality)
            clash_proxy["flow"] = flow

        if network == 'ws':
            clash_proxy["network"] = "ws"
            clash_proxy["ws-path"] = params.get('path', '/')
            clash_proxy["ws-headers"] = {"Host": params.get('host', server)}
        
        # Add other network types if needed (e.g., grpc, h2)

        return clash_proxy
    except Exception as e:
        # print(f"Error parsing VLESS link {vless_link}: {e}")
        return None

def parse_ss(ss_link):
    try:
        if not ss_link.startswith("ss://"):
            return None
        
        # ss://method:password@server:port#tag
        # ss://base64encoded
        
        if '@' in ss_link: # Method and password are not base64 encoded
            # Remove ss://
            core_link = ss_link[5:]
            
            # Split tag if exists
            tag_parts = core_link.split('#', 1)
            core_link_no_tag = tag_parts[0]
            name = requests.utils.unquote(tag_parts[1]) if len(tag_parts) > 1 else 'Unnamed-SS'

            # Split method:password@server:port
            at_parts = core_link_no_tag.split('@', 1)
            if len(at_parts) != 2:
                return None # Invalid format

            method_password_encoded = at_parts[0]
            server_port = at_parts[1]

            method_password_parts = method_password_encoded.split(':', 1)
            method = method_password_parts[0]
            password = method_password_parts[1]

            server, port_str = server_port.split(':', 1)
            port = int(port_str)

        else: # Full link is base64 encoded
            encoded_str = ss_link[5:]
            # Ensure proper padding for base64 decoding
            missing_padding = len(encoded_str) % 4
            if missing_padding:
                encoded_str += '=' * (4 - missing_padding)
            
            decoded_str = base64.b64decode(encoded_str).decode('utf-8')
            
            # Now parse the decoded string: method:password@server:port#tag
            tag_parts = decoded_str.split('#', 1)
            core_link_no_tag = tag_parts[0]
            name = requests.utils.unquote(tag_parts[1]) if len(tag_parts) > 1 else 'Unnamed-SS'

            at_parts = core_link_no_tag.split('@', 1)
            if len(at_parts) != 2:
                return None # Invalid format

            method_password_encoded = at_parts[0]
            server_port = at_parts[1]

            method_password_parts = method_password_encoded.split(':', 1)
            method = method_password_parts[0]
            password = method_password_parts[1]

            server, port_str = server_port.split(':', 1)
            port = int(port_str)

        clash_proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True # Default UDP to true
        }
        return clash_proxy
    except Exception as e:
        # print(f"Error parsing SS link {ss_link}: {e}")
        return None

def parse_trojan(trojan_link):
    try:
        if not trojan_link.startswith("trojan://"):
            return None
        
        # trojan://password@server:port?params#name
        
        # Remove trojan://
        core_link = trojan_link[9:]

        # Split name if exists
        name_parts = core_link.split('#', 1)
        core_link_no_name = name_parts[0]
        name = requests.utils.unquote(name_parts[1]) if len(name_parts) > 1 else 'Unnamed-Trojan'

        # Split password@server:port?params
        at_parts = core_link_no_name.split('@', 1)
        if len(at_parts) != 2:
            return None # Invalid format
        
        password = at_parts[0]
        server_info_params_parts = at_parts[1].split('?', 1)
        server_port_str = server_info_params_parts[0]
        server, port_str = server_port_str.split(':', 1)
        port = int(port_str)

        params = {}
        if len(server_info_params_parts) == 2:
            query_string = server_info_params_parts[1]
            params = parse_qs(query_string)
            # Flatten lists to single values for parameters
            params = {k: v[0] for k, v in params.items()}

        network = params.get('type', 'tcp') # Clash uses 'network' for transport
        tls = True # Trojan always uses TLS
        sni = params.get('sni', server)
        udp = True # Default UDP to true

        clash_proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": udp,
            "tls": tls,
            "servername": sni # sni
        }

        if network == 'ws':
            clash_proxy["network"] = "ws"
            clash_proxy["ws-path"] = params.get('path', '/')
            clash_proxy["ws-headers"] = {"Host": params.get('host', server)}
        
        # Add other network types (e.g., grpc, h2) if needed

        return clash_proxy
    except Exception as e:
        # print(f"Error parsing Trojan link {trojan_link}: {e}")
        return None

def parse_hy2(hy2_link):
    try:
        if not hy2_link.startswith("hy2://"):
            return None
        
        # hy2://<encoded_json_params>#<name>
        core_link = hy2_link[6:]
        name_parts = core_link.split('#', 1)
        encoded_json = name_parts[0]
        
        # Add padding if missing
        missing_padding = len(encoded_json) % 4
        if missing_padding:
            encoded_json += '=' * (4 - missing_padding)

        decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
        params = json.loads(decoded_json_str)

        name = requests.utils.unquote(name_parts[1]) if len(name_parts) > 1 else f"Unnamed-Hy2-{params.get('hostname', '')}"
        
        clash_proxy = {
            "name": name,
            "type": "hysteria2",
            "server": params.get('hostname'),
            "port": params.get('port'),
            "password": params.get('password'),
            "udp": True,
            "tls": True,
            "servername": params.get('sni', params.get('hostname')),
            "skip-cert-verify": not params.get('skipCertVerify', True), # Invert logic: if skipCertVerify is true, then skip-cert-verify should be true
            "alpn": params.get('alpn', ['h3'])[0] # Take the first ALPN if multiple
        }
        
        # Optional fields
        if 'fastOpen' in params:
            clash_proxy['fast-open'] = params['fastOpen']
        if 'mptcp' in params:
            clash_proxy['mptcp'] = params['mptcp']

        return clash_proxy
    except Exception as e:
        # print(f"Error parsing Hysteria2 link {hy2_link}: {e}")
        return None

def parse_tuic(tuic_link):
    try:
        if not tuic_link.startswith("tuic://"):
            return None

        # tuic://<encoded_json_params>#<name>
        core_link = tuic_link[7:]
        name_parts = core_link.split('#', 1)
        encoded_json = name_parts[0]

        # Add padding if missing
        missing_padding = len(encoded_json) % 4
        if missing_padding:
            encoded_json += '=' * (4 - missing_padding)

        decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
        params = json.loads(decoded_json_str)

        name = requests.utils.unquote(name_parts[1]) if len(name_parts) > 1 else f"Unnamed-TUIC-{params.get('uuid', '')}"

        clash_proxy = {
            "name": name,
            "type": "tuic",
            "server": params.get('server'),
            "port": params.get('port'),
            "uuid": params.get('uuid'),
            "password": params.get('password'), # TUICv5 uses password
            "udp": True,
            "tls": True,
            "skip-cert-verify": not params.get('skip_cert_verify', True),
            "servername": params.get('sni', params.get('server')),
            "alpn": params.get('alpn', ['h3'])[0] if params.get('alpn') else 'h3', # Default to h3
            "congestion-controller": params.get('congestion_controller', 'bbr'),
            "reduce-rtt": params.get('reduce_rtt', True),
            "max-udp-relay-datagram-size": params.get('max_udp_relay_datagram_size', 1500)
        }
        
        # Add version if specified
        if 'version' in params:
            clash_proxy['version'] = params['version']

        return clash_proxy
    except Exception as e:
        # print(f"Error parsing TUIC link {tuic_link}: {e}")
        return None

def parse_custom_clash(yaml_content):
    """
    尝试从提供的YAML内容中提取Clash代理节点。
    这里的逻辑需要根据实际提供的yaml结构进行调整。
    假定提供的yaml直接是Clash的proxies列表或者包含proxies键。
    """
    try:
        config = yaml.safe_load(yaml_content)
        if isinstance(config, dict) and 'proxies' in config:
            return config['proxies']
        elif isinstance(config, list): # If the content is just a list of proxies
            return config
        return []
    except yaml.YAMLError as e:
        print(f"Error parsing custom Clash YAML: {e}")
        return []

def get_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def generate_file_hash(content):
    """生成内容的MD5哈希值，用于判断内容是否改变。"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def process_url(session, url, all_proxies, processed_filenames):
    try:
        headers = {'User-Agent': 'Clash'}
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # 检查HTTP错误

        content_type = response.headers.get('Content-Type', '')
        
        # 根据URL或Content-Type判断文件类型
        if 'yaml' in content_type or url.endswith(('.yaml', '.yml', '.meta.yml')):
            # print(f"尝试解析 YAML 内容从 {url}...")
            # 假设这是一个完整的Clash配置或者proxies列表
            proxies_from_url = parse_custom_clash(response.text)
        elif 'text/plain' in content_type or url.endswith(('.txt', '.conf')):
            # print(f"尝试解析纯文本订阅链接从 {url}...")
            proxies_from_url = []
            lines = response.text.splitlines()
            for line in lines:
                if line.startswith("vmess://"):
                    p = parse_vmess(line)
                elif line.startswith("vless://"):
                    p = parse_vless(line)
                elif line.startswith("ss://"):
                    p = parse_ss(line)
                elif line.startswith("trojan://"):
                    p = parse_trojan(line)
                elif line.startswith("hy2://"):
                    p = parse_hy2(line)
                elif line.startswith("tuic://"):
                    p = parse_tuic(line)
                else:
                    # 尝试 base64 解码，通常订阅链接是 base64 编码的
                    try:
                        decoded_line = base64.b64decode(line).decode('utf-8')
                        for sub_link in decoded_line.splitlines():
                            if sub_link.startswith("vmess://"):
                                p = parse_vmess(sub_link)
                            elif sub_link.startswith("vless://"):
                                p = parse_vless(sub_link)
                            elif sub_link.startswith("ss://"):
                                p = parse_ss(sub_link)
                            elif sub_link.startswith("trojan://"):
                                p = parse_trojan(sub_link)
                            elif sub_link.startswith("hy2://"):
                                p = parse_hy2(sub_link)
                            elif sub_link.startswith("tuic://"):
                                p = parse_tuic(sub_link)
                            else:
                                p = None # Unrecognized sub-link
                            if p:
                                proxies_from_url.append(p)
                        continue # Move to next line after base64 processing
                    except (base64.binascii.Error, UnicodeDecodeError):
                        p = None # Not base64 or not a recognized protocol

                if p:
                    proxies_from_url.append(p)
        else:
            print(f"URL: {url} 的内容类型 {content_type} 未知或不受支持，尝试按纯文本处理。")
            proxies_from_url = []
            lines = response.text.splitlines()
            for line in lines:
                if line.startswith("vmess://"):
                    p = parse_vmess(line)
                elif line.startswith("vless://"):
                    p = parse_vless(line)
                elif line.startswith("ss://"):
                    p = parse_ss(line)
                elif line.startswith("trojan://"):
                    p = parse_trojan(line)
                elif line.startswith("hy2://"):
                    p = parse_hy2(line)
                elif line.startswith("tuic://"):
                    p = parse_tuic(line)
                else:
                    # 尝试 base64 解码，通常订阅链接是 base64 编码的
                    try:
                        decoded_line = base64.b64decode(line).decode('utf-8')
                        for sub_link in decoded_line.splitlines():
                            if sub_link.startswith("vmess://"):
                                p = parse_vmess(sub_link)
                            elif sub_link.startswith("vless://"):
                                p = parse_vless(sub_link)
                            elif sub_link.startswith("ss://"):
                                p = parse_ss(sub_link)
                            elif sub_link.startswith("trojan://"):
                                p = parse_trojan(sub_link)
                            elif sub_link.startswith("hy2://"):
                                p = parse_hy2(sub_link)
                            elif sub_link.startswith("tuic://"):
                                p = parse_tuic(sub_link)
                            else:
                                p = None # Unrecognized sub-link
                            if p:
                                proxies_from_url.append(p)
                        continue # Move to next line after base64 processing
                    except (base64.binascii.Error, UnicodeDecodeError):
                        p = None # Not base64 or not a recognized protocol

                if p:
                    proxies_from_url.append(p)

        # 提取文件名（不含扩展名），并规范化为小写
        path = urlparse(url).path
        filename_without_ext = os.path.splitext(os.path.basename(path))[0].lower()
        
        # 对于v.txt，输出文件名为v.yaml
        if filename_without_ext == 'v':
            output_filename_base = 'v'
        elif filename_without_ext == 'configtg':
            output_filename_base = 'configtg'
        else:
            output_filename_base = filename_without_ext.replace('.', '_') # Replace dots in filenames like 520.yaml

        final_output_filename = os.path.join("sc", f"{output_filename_base}.yaml")
        processed_filenames.add(final_output_filename)

        if proxies_from_url:
            print(f"解析内容 ({os.path.basename(final_output_filename)}): {proxies_from_url[0].get('type')}://{proxies_from_url[0].get('uuid', proxies_from_url[0].get('password'))}@{proxies_from_url[0].get('server')}:{proxies_from_url[0].get('port')}...")
            
            unique_proxies = []
            for proxy in proxies_from_url:
                proxy_hash = generate_file_hash(json.dumps(proxy, sort_keys=True))
                if proxy_hash not in all_proxies:
                    unique_proxies.append(proxy)
                    all_proxies[proxy_hash] = proxy
                else:
                    print(f"发现 {os.path.basename(final_output_filename)} 中重复代理，已跳过: {proxy.get('name', 'Unnamed Proxy')}")

            # 创建最终的Clash配置
            final_clash_config = clash_config_template.copy()
            final_clash_config['proxies'] = unique_proxies

            # 填充代理组
            # 提取所有代理名称
            proxy_names = [p['name'] for p in unique_proxies]

            # 填充 "节点选择" 组，确保 "DIRECT" 不在其中
            final_clash_config['proxy-groups'][0]['proxies'] = [p for p in proxy_names if p != 'DIRECT']
            if not final_clash_config['proxy-groups'][0]['proxies']:
                 final_clash_config['proxy-groups'][0]['proxies'] = ['DIRECT'] # If no nodes, default to DIRECT

            # 填充其他代理组
            default_proxies = final_clash_config['proxy-groups'][0]['proxies'] + ['DIRECT'] # All selectable proxies + DIRECT
            for i in range(1, len(final_clash_config['proxy-groups'])):
                group_name = final_clash_config['proxy-groups'][i]['name']
                if group_name in ["国内网站", "百度"]: # 这些组只包含DIRECT
                    final_clash_config['proxy-groups'][i]['proxies'] = ['DIRECT']
                elif group_name in ["国外网站", "TikTok", "YouTube", "Netflix", "Pornhub", "Spotify", 
                                    "Telegram", "谷歌", "微软", "苹果", "游戏", "OpenAI", "Github"]:
                    final_clash_config['proxy-groups'][i]['proxies'] = [p for p in default_proxies if p in [g['name'] for g in final_clash_config['proxy-groups'][0]['proxies']]] # Ensure only valid proxies are added
                    final_clash_config['proxy-groups'][i]['proxies'].insert(0, '节点选择') # Insert '节点选择' as the first option
                    final_clash_config['proxy-groups'][i]['proxies'].append('DIRECT') # Add DIRECT as last fallback
                    # Remove duplicates while maintaining order if '节点选择' or 'DIRECT' were already present
                    seen = set()
                    final_clash_config['proxy-groups'][i]['proxies'] = [x for x in final_clash_config['proxy-groups'][i]['proxies'] if x not in seen and not seen.add(x)]

            # Clean up proxy groups: ensure no empty proxy lists and 'DIRECT' is handled
            for group in final_clash_config['proxy-groups']:
                if not group['proxies'] and group['name'] not in ["国内网站", "百度"]: # For groups that *should* have proxies, if empty, add DIRECT
                    group['proxies'].append('DIRECT')
                
                # Ensure 'DIRECT' is not duplicated and is the last option if present
                if 'DIRECT' in group['proxies']:
                    # Remove all 'DIRECT' instances and re-add one at the end if it's not a direct group
                    if group['type'] != 'direct':
                        group['proxies'] = [p for p in group['proxies'] if p != 'DIRECT']
                        group['proxies'].append('DIRECT')
                    # For 'direct' type groups, ensure only one 'DIRECT'
                    else:
                        group['proxies'] = ['DIRECT']


            # 保存到文件
            print(f"保存配置到 {final_output_filename}...")
            try:
                with open(final_output_filename, 'w', encoding='utf-8') as f:
                    yaml.dump(final_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False,
                              indent=2, width=80)
                print(f"文件 {final_output_filename} 已生成，包含 {len(unique_proxies)} 个去重后的节点。")
            except IOError as e:
                print(f"错误：无法将配置保存到 {final_output_filename}: {e}", file=sys.stderr)
                sys.exit(1) # 文件写入失败，退出并返回错误码
        else:
            print(f"从 {url} 未能提取到有效代理，不生成文件。")

    except requests.RequestException as e:
        print(f"无法获取或解析 {url}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"处理 {url} 时发生意外错误: {e}", file=sys.stderr)
        # 不在此处 sys.exit(1)，因为一个URL的失败不应停止整个工作流
        # 但如果希望任何错误都导致失败，可以在这里加上 sys.exit(1)

def main():
    session = get_session()
    all_proxies = {} # 用于存储所有代理的哈希值，实现去重
    processed_filenames = set()

    print("开始获取并按来源保存每个订阅链接的配置...")
    for url in urls:
        print(f"尝试获取 URL: {url}")
        process_url(session, url, all_proxies, processed_filenames)

    # 清理不再由脚本生成的旧YAML文件
    existing_files = [f for f in os.listdir("sc") if f.endswith((".yaml", ".yml"))]
    for filename in existing_files:
        full_path = os.path.join("sc", filename)
        if full_path not in processed_filenames:
            print(f"删除旧文件: {full_path}")
            os.remove(full_path)

if __name__ == "__main__":
    main()
