import requests
import yaml
import base64
import time
import subprocess
import os
import re
import json
from urllib.parse import urlparse, parse_qs, unquote, quote

# --- Configuration ---
# 节点的来源列表。每个来源可以指定 'url' 和 'format'。
# 'format' 可以是:
# - 'auto': 尝试 Base64 解码，然后尝试 YAML 解析，否则视为纯文本链接。
# - 'base64-links': 强制 Base64 解码，然后解析为多行链接。
# - 'plain-links': 直接解析为多行链接。
# - 'clash-yaml': 强制解析为 Clash YAML 格式，并提取 'proxies' 列表。
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
        "format": "auto"
    },
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
        "format": "auto"
    }
]

CLASH_CORE_VERSION = "v1.19.10" # Mihomo 版本
CLASH_DOWNLOAD_URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{CLASH_CORE_VERSION}/mihomo-linux-amd64-{CLASH_CORE_VERSION}.gz"
CLASH_BIN_PATH = "clash_bin/mihomo"
CLASH_CONFIG_PATH = "clash_config.yaml"
COLLECT_SUB_PATH = "data/collectSub.txt"
CLASH_LOG_PATH = "clash_bin/clash_debug.log" # Clash core will log here

CLASH_API_URL = "http://127.0.0.1:9090"
CLASH_PROXY_URL = "http://127.0.0.1:7890"

SPEED_TEST_URL = "http://ipv4.download.thinkbroadband.com/5MB.zip" # 用于测速的文件
SPEED_TEST_TIMEOUT = 30 # 单个节点测速超时时间

# --- Helper Functions for Format Detection ---

def is_base64(s):
    """简单的Base64字符串启发式检测"""
    if not isinstance(s, str) or not s.strip():
        return False
    try:
        # 尝试解码为UTF-8并检查是否包含常见可打印字符
        decoded_bytes = base64.b64decode(s.strip().replace('-', '+').replace('_', '/'), validate=True)
        decoded_str = decoded_bytes.decode('utf-8')
        # 启发式：如果解码后包含大量非ASCII控制字符或不可打印字符，则可能不是纯文本Base64
        return all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded_str)
    except Exception:
        return False

def is_yaml(s):
    """尝试判断字符串是否是YAML格式 (使用 full_load 以支持更多标签)"""
    if not isinstance(s, str) or not s.strip():
        return False
    try:
        data = yaml.full_load(s)
        return isinstance(data, dict) or isinstance(data, list)
    except yaml.YAMLError:
        return False
    except Exception:
        return False

# --- Core Functions ---

def setup_clash_core():
    """下载并解压 Clash Core"""
    os.makedirs("clash_bin", exist_ok=True)
    if not os.path.exists(CLASH_BIN_PATH):
        print(f"Downloading Clash core from {CLASH_DOWNLOAD_URL}...")
        try:
            response = requests.get(CLASH_DOWNLOAD_URL, stream=True, timeout=300)
            response.raise_for_status()
            with open(CLASH_BIN_PATH + ".gz", 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Decompressing Clash core...")
            subprocess.run(["gunzip", CLASH_BIN_PATH + ".gz"], check=True)
            subprocess.run(["chmod", "+x", CLASH_BIN_PATH], check=True)
            print("Clash core setup complete.")
        except Exception as e:
            print(f"Error setting up Clash core: {e}")
            exit(1)
    else:
        print("Clash core already exists. Skipping download.")

def clean_string_for_yaml(s):
    """移除所有非打印ASCII字符，并替换可能导致YAML问题的特殊字符"""
    # 移除所有非打印ASCII字符，除了常用的空格、制表符、换行符、回车符
    cleaned = ''.join(char for char in s if 32 <= ord(char) <= 126 or char in ('\n', '\t', '\r'))
    # 替换或转义 YAML 中可能引起歧义的字符
    # 例如，YAML 键不能以特定字符开头，也不能包含某些特殊序列
    # 对于 name 字段，我们希望尽可能保留原始名称，但要去除导致解析错误的字符
    # 这里我们只保留 ASCII 打印字符，并尝试URL解码，然后再进行一次清理
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned) # 移除大多数控制字符

def parse_link(link, i):
    """解析各种代理链接并转换为 Clash 配置字典"""
    link = link.strip()
    if not link:
        return None

    # Common function to extract host and port, handling IPv6
    def extract_host_port(netloc_part):
        if netloc_part.startswith('[') and ']' in netloc_part:
            # IPv6 address with port: [::1]:8080
            match = re.match(r'^\[(.*?)\](?::(\d+))?$', netloc_part)
            if match:
                host = match.group(1)
                port = int(match.group(2)) if match.group(2) else None
                return host, port
            else:
                raise ValueError(f"Invalid IPv6 format in netloc: '{netloc_part}'")
        else:
            # IPv4 or hostname
            if ':' in netloc_part:
                host, port_str = netloc_part.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    raise ValueError(f"Invalid port in netloc: '{port_str}'")
                return host, port
            else:
                return netloc_part, None # No port specified

    try:
        if link.startswith("ss://"):
            # SS link format: ss://method:password@server:port#name
            # Or with plugin: ss://method:password@server:port?plugin=...#name
            # Handle potential plugin parameters in the port part
            link_parts = link[5:].split('@', 1)
            if len(link_parts) < 2:
                # If no '@' found, it could be base64 encoded userinfo only, or invalid
                # Try to base64 decode the whole thing if it seems like it
                try:
                    decoded_link = base64.b64decode(link[5:].replace('-', '+').replace('_', '/')).decode('utf-8')
                    decoded_link = clean_string_for_yaml(decoded_link)
                    if '@' in decoded_link:
                        link_parts = decoded_link.split('@', 1)
                    else:
                        raise ValueError("Decoded SS link still missing @")
                except Exception as e:
                    raise ValueError(f"Invalid SS link format (missing @ or incomplete, and not decodable Base64): {e}")

            user_info_encoded = link_parts[0]
            try:
                # Try URL-safe Base64 decode first
                user_info_decoded = base64.b64decode(user_info_encoded.replace('-', '+').replace('_', '/')).decode('utf-8')
                user_info_decoded = clean_string_for_yaml(user_info_decoded)
                method, password = user_info_decoded.split(':', 1)
            except Exception:
                # Fallback to direct split if not base64 or invalid base64 or not 'method:password' after decode
                if ':' not in user_info_encoded:
                    raise ValueError("SS user info not in 'method:password' format after decode or not base64.")
                method, password = user_info_encoded.split(':', 1)
            
            server_port_name_part = link_parts[1]
            
            # Use urlparse to handle server:port and query/fragment
            parsed_server_port_name = urlparse(f"dummy://{server_port_name_part}")
            server, port = extract_host_port(parsed_server_port_name.netloc)

            # Check if port was extracted, if not, try again from the netloc directly
            if port is None:
                if ':' in parsed_server_port_name.netloc:
                    server_part, port_str = parsed_server_port_name.netloc.rsplit(':', 1)
                    server = server_part
                    port = int(port_str)
                else:
                    raise ValueError("SS link missing port information.")
            
            query_params = parse_qs(parsed_server_port_name.query)
            name = unquote(parsed_server_port_name.fragment).strip() if parsed_server_port_name.fragment else f"SS-Proxy-{i}"

            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password
            }

            # Handle SS plugins
            plugin = query_params.get('plugin', [None])[0]
            if plugin:
                plugin_type_match = re.match(r'^(v2ray-plugin|obfs-local)(?:;(.+))?$', plugin)
                if plugin_type_match:
                    plugin_type = plugin_type_match.group(1)
                    plugin_opts_str = plugin_type_match.group(2)
                    plugin_opts = {}
                    if plugin_opts_str:
                        for opt in plugin_opts_str.split(';'):
                            if '=' in opt:
                                key, value = opt.split('=', 1)
                                plugin_opts[key] = value

                    if plugin_type == 'v2ray-plugin':
                        proxy_dict['plugin'] = 'v2ray-plugin'
                        if 'mode' in plugin_opts and plugin_opts['mode'] == 'websocket':
                            ws_opts = {}
                            if 'path' in plugin_opts:
                                ws_opts['path'] = plugin_opts['path']
                            if 'host' in plugin_opts:
                                ws_opts['headers'] = {'Host': plugin_opts['host']}
                            if ws_opts:
                                proxy_dict['ws-opts'] = ws_opts
                            if 'mux' in plugin_opts:
                                proxy_dict['mux'] = plugin_opts['mux'].lower() == 'true'
                        else:
                            proxy_dict['plugin-opts'] = plugin_opts # Generic plugin options
                    elif plugin_type == 'obfs-local':
                        proxy_dict['plugin'] = 'obfs'
                        obfs_opts = {}
                        if 'obfs' in plugin_opts:
                            obfs_opts['mode'] = plugin_opts['obfs']
                        if 'obfs-host' in plugin_opts:
                            obfs_opts['host'] = plugin_opts['obfs-host']
                        if obfs_opts:
                            proxy_dict['obfs-opts'] = obfs_opts
            
            return proxy_dict


        elif link.startswith("vmess://"):
            encoded_data = link[8:]
            # Ensure proper padding for base64 decoding
            missing_padding = len(encoded_data) % 4
            if missing_padding != 0:
                encoded_data += '=' * (4 - missing_padding)
            
            # Replace URL-safe characters for standard base64
            encoded_data = encoded_data.replace('-', '+').replace('_', '/')

            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            decoded_data = clean_string_for_yaml(decoded_data) # Clean after decode
            vmess_data = json.loads(decoded_data)

            name = (vmess_data.get('ps') if vmess_data.get('ps') else f"VMESS-Proxy-{i}").strip()
            server = vmess_data.get('add')
            port = int(vmess_data.get('port'))
            uuid = vmess_data.get('id')
            alterId_raw = vmess_data.get('aid', '0')
            alterId = int(alterId_raw) if str(alterId_raw).isdigit() else 0
            cipher = vmess_data.get('scy', 'auto')

            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": alterId,
                "cipher": cipher
            }

            network = vmess_data.get('net', 'tcp')
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in vmess_data:
                    ws_opts['path'] = vmess_data['path']
                if 'host' in vmess_data and vmess_data['host']: # Ensure host is not empty
                    ws_opts['headers'] = {'Host': vmess_data['host']}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in vmess_data:
                    grpc_opts['service-name'] = vmess_data['serviceName']
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2':
                h2_opts = {}
                if 'path' in vmess_data:
                    h2_opts['path'] = vmess_data['path']
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            if vmess_data.get('tls', '0') == 'tls':
                proxy_dict['tls'] = True
                # Prefer 'sni' for servername, fallback to 'host' if 'sni' is not present
                if 'sni' in vmess_data and vmess_data['sni']:
                    proxy_dict['servername'] = vmess_data['sni']
                elif 'host' in vmess_data and vmess_data['host']:
                    proxy_dict['servername'] = vmess_data['host']
                
                if vmess_data.get('allowInsecure', '0') == '1':
                    proxy_dict['skip-cert-verify'] = True
                if 'alpn' in vmess_data and vmess_data['alpn']:
                    proxy_dict['alpn'] = [s.strip() for s in vmess_data['alpn'].split(',') if s.strip()]

            # Handle obfs and type for older Vmess links or specific clients
            if vmess_data.get('type') == 'http' and network == 'tcp':
                proxy_dict['obfs'] = 'http'
            elif vmess_data.get('obfs') == 'websocket' and network == 'tcp':
                # This is a bit redundant if 'network' is already 'ws'
                # But ensures older links are correctly mapped
                proxy_dict['network'] = 'ws'
                ws_opts = proxy_dict.get('ws-opts', {})
                if 'obfs-host' in vmess_data and vmess_data['obfs-host']:
                    ws_opts['headers'] = {'Host': vmess_data['obfs-host']}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts

            return proxy_dict

        elif link.startswith("vless://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
            if '@' not in userinfo_part:
                raise ValueError("Invalid VLESS link format (missing @ in userinfo).")
            
            uuid = userinfo_part.split('@')[0]
            server_port_str = userinfo_part.split('@')[1]

            server, port = extract_host_port(server_port_str)
            if port is None:
                raise ValueError("VLESS link missing port information.")

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"VLESS-Proxy-{i}").strip()

            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
            }

            if 'tls' in params:
                proxy_dict['tls'] = params['tls'][0].lower() == 'true'
            if 'flow' in params:
                proxy_dict['flow'] = params['flow'][0]
            if 'sni' in params and params['sni'][0]:
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',') if s.strip()]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'
            
            if 'security' in params and params['security'][0].lower() == 'reality':
                proxy_dict['reality-opts'] = {}
                if 'pbk' in params and params['pbk'][0]:
                    proxy_dict['reality-opts']['publicKey'] = params['pbk'][0]
                if 'sid' in params and params['sid'][0]:
                    proxy_dict['reality-opts']['shortId'] = params['sid'][0]
                if 'spx' in params and params['spx'][0]:
                    proxy_dict['reality-opts']['spiderX'] = params['spx'][0]
            if 'fp' in params and params['fp'][0]:
                proxy_dict['tls'] = True
                proxy_dict['client-fingerprint'] = params['fp'][0]

            network = params.get('type', ['tcp'])[0]
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params and params['path'][0]:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params and params['host'][0]:
                    ws_opts['headers'] = {'Host': params['host'][0]}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in params and params['serviceName'][0]:
                    grpc_opts['service-name'] = params['serviceName'][0]
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2':
                h2_opts = {}
                if 'path' in params and params['path'][0]:
                    h2_opts['path'] = params['path'][0]
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            return proxy_dict

        elif link.startswith("trojan://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
            if '@' not in userinfo_part:
                raise ValueError("Invalid Trojan link format (missing @ in userinfo).")

            password = userinfo_part.split('@')[0]
            server_port_str = userinfo_part.split('@')[1]
            
            server, port = extract_host_port(server_port_str)
            if port is None:
                raise ValueError("Trojan link missing port information.")

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"Trojan-Proxy-{i}").strip()

            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "tls": True # Trojan always implies TLS
            }

            if 'sni' in params and params['sni'][0]:
                proxy_dict['servername'] = params['sni'][0]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',') if s.strip()]

            network = params.get('type', ['tcp'])[0]
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params and params['path'][0]:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params and params['host'][0]:
                    ws_opts['headers'] = {'Host': params['host'][0]}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in params and params['serviceName'][0]:
                    grpc_opts['service-name'] = params['serviceName'][0]
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            
            if 'allowInsecure' in params: # Trojan also has allowInsecure
                proxy_dict['skip-cert-verify'] = params['allowInsecure'][0].lower() == '1'

            return proxy_dict
            
        elif link.startswith("hy2://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
            if '@' not in userinfo_part:
                raise ValueError("Invalid Hysteria2 link format (missing @ in userinfo).")

            auth = userinfo_part.split('@')[0]
            server_port_str = userinfo_part.split('@')[1]

            server, port = extract_host_port(server_port_str)
            if port is None:
                raise ValueError("Hysteria2 link missing port information.")

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"Hysteria2-Proxy-{i}").strip()

            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": auth,
                "tls": True,
            }

            if 'insecure' in params:
                proxy_dict['insecure'] = params['insecure'][0].lower() == '1'
            if 'sni' in params and params['sni'][0]:
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',') if s.strip()]

            # Hysteria2 specific options
            if 'fastopen' in params:
                proxy_dict['fast-open'] = params['fastopen'][0].lower() == '1'
            if 'mptcp' in params:
                proxy_dict['mptcp'] = params['mptcp'][0].lower() == '1'
            if 'up' in params:
                proxy_dict['up'] = int(params['up'][0])
            if 'down' in params:
                proxy_dict['down'] = int(params['down'][0])
            if 'obfs' in params and params['obfs'][0] == 'salamander':
                proxy_dict['obfs'] = 'salamander'
                if 'obfs-password' in params and params['obfs-password'][0]:
                    proxy_dict['obfs-opts'] = {'password': params['obfs-password'][0]}
            if 'peer' in params and params['peer'][0]: # Renamed from 'sni' by some clients, can be servername
                proxy_dict['servername'] = params['peer'][0]

            return proxy_dict
        
        elif link.startswith("ssr://"):
            # SSR links are often base64 encoded payload
            # ssr://<base64_encoded_server_info_and_params>
            encoded_payload = link[6:]
            if '/?' in encoded_payload:
                encoded_payload = encoded_payload.split('/?')[0] # Remove query and fragment before decoding

            missing_padding = len(encoded_payload) % 4
            if missing_padding != 0:
                encoded_payload += '=' * (4 - missing_padding)
            
            decoded_payload_bytes = base64.b64decode(encoded_payload.replace('-', '+').replace('_', '/'))
            # Try decoding with 'utf-8' and then 'latin-1' or 'iso-8859-1' if utf-8 fails for names
            try:
                decoded_payload = decoded_payload_bytes.decode('utf-8')
            except UnicodeDecodeError:
                decoded_payload = decoded_payload_bytes.decode('latin-1') # Fallback for non-UTF8 chars

            decoded_payload = clean_string_for_yaml(decoded_payload) # Clean after decode
            
            # Extract server info (server:port:protocol:method:obfs:password)
            server_info_parts = decoded_payload.split(':')
            if len(server_info_parts) < 6:
                raise ValueError("Invalid SSR link format (not enough parts in server info).")
            
            server = server_info_parts[0]
            port = int(server_info_parts[1])
            protocol = server_info_parts[2]
            method = server_info_parts[3]
            obfs = server_info_parts[4]
            password_encoded = server_info_parts[5]
            
            # Decode password - it's base64 encoded
            password_bytes = base64.b64decode(password_encoded.replace('-', '+').replace('_', '/'))
            try:
                password = password_bytes.decode('utf-8')
            except UnicodeDecodeError:
                password = password_bytes.decode('latin-1')
            password = clean_string_for_yaml(password)

            query_params = {} # Initialize query_params
            name = f"SSR-Proxy-{i}"

            # Handle query parameters and fragment (remarks)
            if '/?' in link:
                fragment_and_params_str = link.split('/?', 1)[1]
                params_part = fragment_and_params_str.split('#', 1)
                
                if params_part[0]: # Check if there are actual query parameters
                    query_params = parse_qs(params_part[0])
                
                if len(params_part) > 1:
                    # Fragment is the name, it's URL-encoded and potentially base64
                    name_fragment_encoded = params_part[1]
                    try:
                        # Try base64 decode if it looks like it
                        name_bytes = base64.b64decode(name_fragment_encoded.replace('-', '+').replace('_', '/'))
                        try:
                            name_decoded = name_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            name_decoded = name_bytes.decode('latin-1')
                        name = unquote(name_decoded).strip()
                    except Exception:
                        name = unquote(name_fragment_encoded).strip() # Fallback to direct unquote
            
            proxy_dict = {
                "name": clean_string_for_yaml(name),
                "type": "ssr",
                "server": server,
                "port": port,
                "protocol": protocol,
                "cipher": method,
                "obfs": obfs,
                "password": password
            }

            if 'protoparam' in query_params and query_params['protoparam'][0]:
                proxy_dict['protocol-param'] = unquote(query_params['protoparam'][0])
            if 'obfsparam' in query_params and query_params['obfsparam'][0]:
                proxy_dict['obfs-param'] = unquote(query_params['obfsparam'][0])
            
            return proxy_dict


    except Exception as e:
        print(f"Warning: Failed to parse link '{link}'. Error: {e}")
    return None

def fetch_and_parse_nodes():
    """从配置的来源获取并解析所有节点"""
    all_parsed_proxies = []
    seen_proxy_names = set() # 用于跟踪已见的代理名称 (在函数开始时初始化一次)

    for source in NODES_SOURCES:
        url = source["url"]
        node_format = source.get("format", "auto")
        print(f"Fetching nodes from: {url} (Format: {node_format})")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            content = response.text

            # Always clean non-printable characters from the raw content first
            content = clean_string_for_yaml(content)

            processed_content = content
            if node_format == "base64-links" or (node_format == "auto" and is_base64(content)):
                try:
                    processed_content = base64.b64decode(content.replace('-', '+').replace('_', '/')).decode('utf-8')
                    processed_content = clean_string_for_yaml(processed_content) # Clean again after base64 decode
                    print(f"Successfully decoded content from base64 for {url}")
                except Exception as e:
                    print(f"Warning: Failed to base64 decode {url}. Treating as plain text. Error: {e}")
                    processed_content = content # Fallback to original cleaned content

            is_yaml_content = False
            yaml_data_from_content = None
            if node_format == "clash-yaml" or (node_format == "auto" and is_yaml(processed_content)):
                try:
                    yaml_data_from_content = yaml.full_load(processed_content)
                    if isinstance(yaml_data_from_content, dict) and 'proxies' in yaml_data_from_content and isinstance(yaml_data_from_content['proxies'], list):
                        is_yaml_content = True
                except yaml.YAMLError as e:
                    print(f"Warning: Failed to parse YAML from {url}. Error: {e}")
                    print("--- Partial Content for Debugging (first 50 lines) ---")
                    debug_lines = processed_content.splitlines()
                    for i, line in enumerate(debug_lines[:50]):
                        print(f"Line {i+1}: {line}")
                    print("---------------------------------------------")
                except Exception as e:
                    print(f"Warning: An unexpected error occurred during YAML check for {url}. Error: {e}")
            
            if is_yaml_content:
                print(f"Successfully parsed Clash YAML proxies from {url}")
                for proxy_dict in yaml_data_from_content['proxies']:
                    if isinstance(proxy_dict, dict) and 'name' in proxy_dict and 'type' in proxy_dict:
                        original_name = clean_string_for_yaml(unquote(str(proxy_dict["name"]))) # Ensure name is string and unquote
                        proxy_dict["name"] = original_name

                        if proxy_dict["name"] in seen_proxy_names:
                            counter = 1
                            new_name = f"{proxy_dict['name']}-{counter}"
                            while new_name in seen_proxy_names:
                                counter += 1
                                new_name = f"{proxy_dict['name']}-{counter}"
                            proxy_dict["name"] = new_name
                            print(f"Duplicate proxy name '{original_name}' found. Renaming to '{new_name}'.")
                        
                        seen_proxy_names.add(proxy_dict["name"])
                        all_parsed_proxies.append(proxy_dict)
                    else:
                        print(f"Warning: Invalid proxy entry in YAML from {url}: {proxy_dict}")
                continue
            elif node_format == "clash-yaml":
                print(f"Error: Format explicitly set to 'clash-yaml' for {url}, but content is not valid Clash YAML. Skipping.")
                continue

            raw_links = processed_content.splitlines()
            print(f"Processing {len(raw_links)} raw links from {url}")
            for i, link in enumerate(raw_links):
                if not link.strip():
                    continue
                proxy = parse_link(link.strip(), i)
                if proxy:
                    original_name = proxy["name"]
                    if original_name in seen_proxy_names:
                        counter = 1
                        new_name = f"{original_name}-{counter}"
                        while new_name in seen_proxy_names:
                            counter += 1
                            new_name = f"{original_name}-{counter}"
                        proxy["name"] = new_name
                        print(f"Duplicate proxy name '{original_name}' found. Renaming to '{new_name}'.")

                    seen_proxy_names.add(proxy["name"])
                    all_parsed_proxies.append(proxy)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while processing {url}: {e}")
    
    return all_parsed_proxies


def generate_clash_config(proxies):
    """生成 Clash 配置文件"""
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "debug",
        "external-controller": "127.0.0.1:9090",
        "secret": "",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "测速",
                "type": "select",
                "proxies": [p["name"] for p in proxies] if proxies else ["DIRECT"]
            },
            {
                "name": "DIRECT",
                "type": "direct"
            },
            {
                "name": "REJECT",
                "type": "reject"
            }
        ],
        "rules": [
            "MATCH,测速"
        ]
    }
    with open(CLASH_CONFIG_PATH, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"Clash config generated at {CLASH_CONFIG_PATH}")


def start_clash():
    """启动 Clash Core"""
    print("Starting Clash core...")
    os.makedirs(os.path.dirname(CLASH_LOG_PATH), exist_ok=True)
    with open(CLASH_LOG_PATH, 'w') as log_file: # 每次启动前清空日志
        log_file.write(f"--- Clash Core Log Start ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n")
    
    # 使用 Popen 而不是 run，并捕获 stdout 和 stderr
    clash_process = subprocess.Popen(
        [CLASH_BIN_PATH, "-f", CLASH_CONFIG_PATH, "-d", "."],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1, # Line-buffered output
        universal_newlines=True # Ensure correct newline handling
    )

    # 立即读取 stdout/stderr，并写入日志文件
    # 使用非阻塞读取，或者在一个单独的线程中读取，这里简化处理
    # 更好的方式是使用 select.select 或 threading.Thread
    # 但为了简单，我们先等待一小段时间，然后读取已有的输出
    time.sleep(2)

    api_ready = False
    for i in range(10):
        if clash_process.poll() is not None: # Check if process has exited
            print("Clash process exited prematurely.")
            clash_stdout, clash_stderr = clash_process.communicate(timeout=5)
            with open(CLASH_LOG_PATH, 'a') as log_file:
                log_file.write("\n--- Clash Process STDOUT/STDERR (on exit) ---\n")
                log_file.write(clash_stdout)
                log_file.write(clash_stderr)
                log_file.write("\n--- End of Clash Process STDOUT/STDERR (on exit) ---\n")
            raise Exception(f"Clash core exited prematurely with code {clash_process.returncode}. Check log for details.")

        try:
            response = requests.get(f"{CLASH_API_URL}/configs", timeout=2)
            if response.status_code == 200:
                print("Clash API is reachable.")
                api_ready = True
                break
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            print(f"Error checking Clash API: {e}")
        time.sleep(2)

    if not api_ready:
        # If API not ready, try to read remaining output before raising exception
        clash_stdout, clash_stderr = clash_process.communicate(timeout=5)
        with open(CLASH_LOG_PATH, 'a') as log_file:
            log_file.write("\n--- Clash Process STDOUT/STDERR (failed to start) ---\n")
            log_file.write(clash_stdout)
            log_file.write(clash_stderr)
            log_file.write("\n--- End of Clash Process STDOUT/STDERR (failed to start) ---\n")
        raise Exception("Clash API did not become reachable within expected time.")

    print("Clash core started.")
    return clash_process


def test_proxy(proxy_name):
    """测试单个代理的速度"""
    try:
        headers = {'Content-Type': 'application/json'}
        payload = {"name": proxy_name}
        
        response = requests.get(f"{CLASH_API_URL}/proxies", timeout=5)
        response.raise_for_status()

        response = requests.put(f"{CLASH_API_URL}/proxies/%E6%B5%8B%E9%80%9F", # '测速' URL 编码
                                 headers=headers, json=payload, timeout=5)
        response.raise_for_status()
        print(f"Switched proxy to: {proxy_name}")
        time.sleep(1)

        start_time = time.time()
        with requests.get(SPEED_TEST_URL, stream=True, timeout=SPEED_TEST_TIMEOUT, proxies={'http': CLASH_PROXY_URL, 'https': CLASH_PROXY_URL}) as r:
            r.raise_for_status()
            total_size = 0
            for chunk in r.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size >= 5 * 1024 * 1024:
                    break
            
        end_time = time.time()
        duration = end_time - start_time
        
        if duration > 0:
            speed_mbps = (total_size * 8) / (1024 * 1024 * duration)
            print(f"Proxy: {proxy_name} # Speed: {speed_mbps:.2f} Mbps")
            return f"Proxy: {proxy_name} # 速度: {speed_mbps:.2f} Mbps"
        else:
            print(f"Proxy: {proxy_name} # Speed: 0 Mbps (Duration too short)")
            return f"Proxy: {proxy_name} # 速度: 0 Mbps (Duration too short)"

    except requests.exceptions.Timeout:
        print(f"Proxy: {proxy_name} # Speed: 测试超时")
        return f"Proxy: {proxy_name} # 速度: 测试超时"
    except requests.exceptions.RequestException as e:
        print(f"Proxy: {proxy_name} # Speed: 测试失败 (通过 {CLASH_PROXY_URL}): {e}")
        return f"Proxy: {proxy_name} # 速度: 测试失败 (通过 {CLASH_PROXY_URL}): {e}"
    except Exception as e:
        print(f"An unexpected error occurred during test for {proxy_name}: {e}")
        return f"Proxy: {proxy_name} # 速度: 未知错误: {e}"


def main():
    os.makedirs("data", exist_ok=True)
    os.makedirs(os.path.dirname(CLASH_LOG_PATH), exist_ok=True)
    open(CLASH_LOG_PATH, 'w').close() # 清空旧日志文件

    setup_clash_core()
    proxies = fetch_and_parse_nodes()

    if not proxies:
        print("No valid proxies found to test.")
        with open(COLLECT_SUB_PATH, 'w', encoding='utf-8') as f:
            f.write("# 节点测速结果 - 无可用节点\n")
        return

    generate_clash_config(proxies)

    clash_process = None
    try:
        clash_process = start_clash()
        results = []
        results.append(f"# 节点测速结果 - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 添加默认的DIRECT和REJECT组的测试结果（通常无法测速，只是占位）
        results.append("Proxy: DIRECT # 速度: (Clash内置组)")
        results.append("Proxy: REJECT # 速度: (Clash内置组)")
        results.append("Proxy: COMPATIBLE # 速度: (Clash内置组)")
        results.append("Proxy: PASS # 速度: (Clash内置组)")
        results.append("Proxy: REJECT-DROP # 速度: (Clash内置组)")


        for proxy in proxies:
            result = test_proxy(proxy["name"])
            results.append(result)
            
        with open(COLLECT_SUB_PATH, 'w', encoding='utf-8') as f:
            for line in results:
                f.write(line + "\n")
        print(f"Speed test results saved to {COLLECT_SUB_PATH}")

    finally:
        if clash_process:
            print("Terminating Clash core...")
            clash_stdout, clash_stderr = clash_process.communicate(timeout=5)
            with open(CLASH_LOG_PATH, 'a') as log_file:
                log_file.write("\n--- Clash Process STDOUT/STDERR (on exit) ---\n")
                log_file.write(clash_stdout)
                log_file.write(clash_stderr)
                log_file.write("\n--- End of Clash Process STDOUT/STDERR (on exit) ---\n")
            
            clash_process.terminate()
            clash_process.wait(timeout=10)
            print("Clash core terminated.")

if __name__ == "__main__":
    main()
