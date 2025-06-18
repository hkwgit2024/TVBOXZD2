import requests
import os
import subprocess
import time
import datetime
import json
import shutil
import tarfile
import gzip
import urllib.parse
import base64
import yaml # This library is required for YAML parsing and dumping

# --- Configuration ---
NODES_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
OUTPUT_FILE = "data/collectSub.txt"
CLASH_CONFIG_FILE = "clash_config.yaml"
CLASH_API_PORT = 9090 # Clash external controller port
CLASH_PROXY_HTTP_PORT = 7890 # Clash HTTP proxy port
# 更改测速URL以尝试提高成功率和获取更多信息
TEST_FILE_URL = "http://ipv4.download.thinkbroadband.com/5MB.zip" # 5MB测试文件
# TEST_FILE_URL = "http://cachefly.cachefly.net/100mb.test" # 100MB测试文件，如果5MB成功可以尝试这个

# Clash Meta (mihomo) Version and Download URL
CLASH_VERSION_TO_DOWNLOAD = "v1.19.10"
CLASH_DOWNLOAD_BASE_URL = "https://github.com/MetaCubeX/mihomo/releases/download"
CLASH_ARCHIVE_NAME = f"mihomo-linux-amd64-{CLASH_VERSION_TO_DOWNLOAD}.gz"
CLASH_DOWNLOAD_URL = f"{CLASH_DOWNLOAD_BASE_URL}/{CLASH_VERSION_TO_DOWNLOAD}/{CLASH_ARCHIVE_NAME}"

CLASH_BIN_DIR = "clash_bin"
CLASH_EXECUTABLE_NAME = "mihomo"
CLASH_FULL_PATH = os.path.join(CLASH_BIN_DIR, CLASH_EXECUTABLE_NAME)

# Global variable to store Clash log path (for main function to access)
CLASH_LOG_FILE = os.path.join(CLASH_BIN_DIR, "clash_debug.log")

# --- Helper Functions ---

def download_and_extract_clash_core(url, dest_dir, executable_name):
    """
    Downloads and extracts Clash core to dest_dir.
    Checks if the executable already exists and is executable to avoid re-downloading.
    Handles .tar.gz, .zip, and .gz (gzipped executable) formats.
    Returns path to executable or None on failure.
    """
    os.makedirs(dest_dir, exist_ok=True)
    
    clash_exec_path = os.path.join(dest_dir, executable_name)

    # Check if executable already exists and is executable
    if os.path.exists(clash_exec_path) and os.path.isfile(clash_exec_path) and os.access(clash_exec_path, os.X_OK):
        print(f"[DEBUG] Executable already exists and is executable at {clash_exec_path}. Skipping download.")
        return clash_exec_path

    print(f"[DEBUG] Executable not found or not executable. Attempting to download from: {url}")
    try:
        print(f"[DEBUG] Initiating download of {url}...")
        response = requests.get(url, stream=True)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        
        filename = url.split('/')[-1]
        temp_archive_path = os.path.join(dest_dir, filename)

        with open(temp_archive_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[DEBUG] Downloaded archive/file to: {temp_archive_path}")

        extracted_name = None
        if filename.endswith(".tar.gz"):
            print(f"[DEBUG] Extracting .tar.gz archive: {temp_archive_path}")
            with tarfile.open(temp_archive_path, "r:gz") as tar:
                all_members = [m.name for m in tar.getmembers()]
                print(f"[DEBUG] Archive members: {all_members}")

                members = [m for m in tar.getmembers() if m.isfile() and m.name == executable_name]
                if not members:
                    members = [m for m in tar.getmembers() if m.isfile() and m.name.startswith(f"{executable_name}-")]

                if not members:
                    print(f"[ERROR] Executable '{executable_name}' or starting with '{executable_name}-' not found inside .tar.gz archive.")
                    raise Exception("Executable not found inside .tar.gz archive.")
                
                clash_member = members[0]
                print(f"[DEBUG] Found executable member: {clash_member.name}. Extracting...")
                tar.extract(clash_member, path=dest_dir)
                extracted_name = os.path.join(dest_dir, clash_member.name)
                print(f"[DEBUG] Extracted to: {extracted_name}")

        elif filename.endswith(".zip"):
            print(f"[DEBUG] Extracting .zip archive: {temp_archive_path}")
            subprocess.run(["unzip", "-o", temp_archive_path, "-d", dest_dir], check=True, capture_output=True, text=True)
            print(f"[DEBUG] Zip extraction complete to {dest_dir}. Searching for executable...")
            
            found_paths = []
            for root, _, files in os.walk(dest_dir):
                for f_name in files:
                    if f_name == executable_name or f_name.startswith(f"{executable_name}-") and not f_name.endswith(('.zip', '.tar.gz', '.gz')):
                        found_paths.append(os.path.join(root, f_name))
            
            if found_paths:
                extracted_name = found_paths[0]
                print(f"[DEBUG] Found extracted executable at: {extracted_name}")
            else:
                print(f"[ERROR] Executable '{executable_name}' or similar not found inside .zip archive after extraction.")
                raise Exception("Executable not found inside .zip archive after extraction.")

        elif filename.endswith(".gz"):
            print(f"[DEBUG] Decompressing .gz file: {temp_archive_path}")
            decompressed_path = os.path.join(dest_dir, executable_name)
            try:
                with gzip.open(temp_archive_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                extracted_name = decompressed_path
                print(f"[DEBUG] Decompressed to: {extracted_name}")
            except Exception as e:
                print(f"[ERROR] Failed to decompress .gz file: {e}")
                raise Exception(f"Failed to decompress .gz file: {e}")
        else:
            print(f"[ERROR] Unsupported archive/file format: {filename}. Only .tar.gz, .zip, or .gz are supported.")
            raise Exception("Unsupported archive/file format.")

        if extracted_name and extracted_name != clash_exec_path:
            print(f"[DEBUG] Moving extracted executable from '{extracted_name}' to '{clash_exec_path}'...")
            shutil.move(extracted_name, clash_exec_path)
            print(f"[DEBUG] Moved successfully.")

        print(f"[DEBUG] Setting executable permission for: {clash_exec_path}")
        subprocess.run(["chmod", "+x", clash_exec_path], check=True)
        print(f"[DEBUG] Executable now ready at: {clash_exec_path}")
        return clash_exec_path
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Network error during download: {e}")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Extraction/decompression failed. Stderr:\n{e.stderr}\nStdout:\n{e.stdout}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during download or extraction: {e}")
        return None

def start_clash(clash_executable_path, config_file_path):
    """Starts Clash in the background and verifies API availability."""
    try:
        print(f"Starting Clash from {clash_executable_path} with config {config_file_path}...")
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(CLASH_LOG_FILE), exist_ok=True)
        
        # Redirect stdout and stderr to a log file
        with open(CLASH_LOG_FILE, "w") as log_file:
            # Set ulimit -n for the current process before starting Clash
            command = f"ulimit -n 65535 && {clash_executable_path} -f {config_file_path}"
            
            process = subprocess.Popen(
                command,
                stdout=log_file, # Redirect stdout to file
                stderr=log_file, # Redirect stderr to file
                text=True,
                shell=True # Important: run with shell=True to execute ulimit
            )
        
        time.sleep(3) 

        if process.poll() is not None:
            # If Clash exited prematurely, it might have written to the log file
            print(f"Clash exited prematurely. Checking log file: {CLASH_LOG_FILE}")
            try:
                with open(CLASH_LOG_FILE, "r") as f:
                    print("Clash Log (tail):")
                    # Print last few lines of the log
                    log_lines = f.readlines()
                    for line in log_lines[-20:]: # Print last 20 lines
                        print(line.strip())
            except Exception as e:
                print(f"Could not read Clash log file: {e}")
            return None
        
        print(f"Clash started (PID: {process.pid}). Waiting for API to become available...")
        
        api_url = f"http://127.0.0.1:{CLASH_API_PORT}/configs"
        for i in range(15):
            try:
                response = requests.get(api_url, timeout=2)
                if response.status_code == 200:
                    print("Clash API is reachable.")
                    return process
            except requests.exceptions.ConnectionError:
                print(f"Clash API not yet available, retrying... ({i+1}/15)")
                time.sleep(2)
        print("Clash API did not become available after multiple retries.")
        return None

    except Exception as e:
        print(f"Error starting Clash: {e}")
        return None

def stop_clash(clash_process):
    """Stops the Clash process gracefully."""
    if clash_process and clash_process.poll() is None:
        print("Stopping Clash process...")
        try:
            clash_process.terminate()
            clash_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Clash did not terminate gracefully, sending SIGKILL.")
            clash_process.kill()
            clash_process.wait(timeout=5)
        print("Clash process stopped.")
    else:
        print("Clash process was not running or already stopped.")

def get_clash_proxies_names():
    """Fetches all available proxy names from Clash API."""
    api_url = f"http://127.0.0.1:{CLASH_API_PORT}/proxies"
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Filter out built-in proxy types that are not actual nodes
        proxy_names = [
            name for name, proxy_info in data['proxies'].items() 
            if proxy_info.get('type') not in ['Selector', 'URLTest', 'Fallback', 'Direct', 'Reject']
        ]
        print(f"Discovered Clash proxy names for testing: {proxy_names}")
        return proxy_names
    except Exception as e:
        print(f"Failed to get Clash proxy names via API: {e}")
        return []

def set_clash_proxy_group_selection(group_name, proxy_name):
    """Sets the selected proxy for a specific proxy group via Clash API."""
    api_url = f"http://127.0.0.1:{CLASH_API_PORT}/proxies/{group_name}"
    headers = {'Content-Type': 'application/json'}
    payload = {'name': proxy_name}
    try:
        response = requests.put(api_url, headers=headers, data=json.dumps(payload), timeout=5)
        response.raise_for_status()
        # print(f"Clash proxy group '{group_name}' set to '{proxy_name}'.") # Commented for less verbose output
        return True
    except Exception as e:
        print(f"Failed to set Clash proxy group selection for '{group_name}' to '{proxy_name}': {e}")
        return False

def test_download_speed(url, proxy_address, file_size_bytes=5 * 1024 * 1024): # Adjusted default test size for 5MB.zip
    """Tests download speed using the specified proxy."""
    proxies = {
        "http": proxy_address,
        "https": proxy_address,
    }
    
    start_time = time.time()
    downloaded_bytes = 0
    try:
        response = requests.get(url, proxies=proxies, stream=True, timeout=90) # Increased timeout to 90 seconds
        response.raise_for_status()

        # Check content-length from headers if available, for more accurate comparison
        expected_size = int(response.headers.get('content-length', file_size_bytes))
        
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                downloaded_bytes += len(chunk)
                # Stop if we've downloaded enough, or if response is unexpectedly smaller
                if downloaded_bytes >= expected_size or len(chunk) == 0:
                    break
        
        end_time = time.time()
        duration = end_time - start_time

        if duration > 0 and downloaded_bytes > 0:
            speed_mb_s = (downloaded_bytes / (1024 * 1024)) / duration
            return speed_mb_s
        else:
            # This might happen if the file is smaller than expected or connection immediately drops
            print(f"No data downloaded or zero duration for {url} (Downloaded: {downloaded_bytes} bytes).")
            return None
    except requests.exceptions.Timeout:
        print(f"下载超时 (通过 {proxy_address}).")
        return None
    except requests.exceptions.ConnectionError:
        print(f"连接错误 (通过 {proxy_address}).")
        return None
    except requests.exceptions.RequestException as e:
        print(f"下载失败 (通过 {proxy_address}): {e}")
        return None
    except Exception as e:
        print(f"发生未知错误 during speed test: {e}")
        return None

# --- Node Link Parsing Functions ---

def parse_ss_link(link_str, index):
    # Format: ss://[base64-encoded-userinfo]@server:port#name or ss://method:password@server:port#name
    try:
        # Use urlparse for initial breakdown, it handles @ and # well
        parsed_url = urllib.parse.urlparse(link_str)
        
        if not parsed_url.netloc: # netloc contains userinfo@host:port
            print(f"[ERROR] Invalid SS link format (missing network location/credentials): '{link_str}'")
            return None

        # Userinfo part (method:password)
        userinfo_raw = parsed_url.username
        if not userinfo_raw:
             print(f"[ERROR] Invalid SS link format (missing userinfo before @): '{link_str}'")
             return None

        method_password_raw = userinfo_raw
        try:
            # Try to base64 decode the userinfo_raw
            missing_padding = len(userinfo_raw) % 4
            if missing_padding:
                userinfo_raw += '=' * (4 - missing_padding)
            decoded_bytes = base64.urlsafe_b64decode(userinfo_raw)
            method_password_raw = decoded_bytes.decode('utf-8')
        except Exception:
            # If decoding fails, assume it's not base64 encoded (direct method:password)
            pass

        if ':' not in method_password_raw:
            print(f"[ERROR] Invalid SS link format (malformed method:password in '{method_password_raw}'): '{link_str}'")
            return None
        method, password = method_password_raw.split(':', 1)

        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"SS-Proxy-{index}"
        
        if not (server and port is not None): # Check for server and valid port
            print(f"[ERROR] Invalid SS link (missing server or port): '{link_str}'")
            return None

        return {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password
        }
    except Exception as e:
        print(f"[ERROR] Failed to parse SS link '{link_str}': {e}")
        return None

def parse_trojan_link(link_str, index):
    # Format: trojan://password@server:port?params#name
    try:
        parsed_url = urllib.parse.urlparse(link_str)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"Trojan-Proxy-{index}"
        
        if not (password and server and port): # Basic validation
            print(f"[ERROR] Invalid Trojan link (missing password, server or port): '{link_str}'")
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        proxy_config = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "tls": True # Trojan implies TLS
        }
        
        if 'sni' in query_params:
            proxy_config['sni'] = query_params['sni'][0]
        elif 'peer' in query_params: # Some links use peer instead of sni
            proxy_config['sni'] = query_params['peer'][0]
        
        if 'alpn' in query_params:
            proxy_config['alpn'] = query_params['alpn'][0].split(',')

        if 'skipCertVerify' in query_params and query_params['skipCertVerify'][0] == '1':
            proxy_config['skip-cert-verify'] = True

        # Common network/transport options (ws)
        if 'type' in query_params and query_params['type'][0] == 'ws':
            proxy_config['network'] = 'ws'
            proxy_config['ws-opts'] = {}
            if 'path' in query_params:
                proxy_config['ws-opts']['path'] = query_params['path'][0]
            if 'host' in query_params:
                proxy_config['ws-opts']['headers'] = {'Host': query_params['host'][0]}
        
        return proxy_config
    except Exception as e:
        print(f"[ERROR] Failed to parse Trojan link '{link_str}': {e}")
        return None

def parse_vless_link(link_str, index):
    # Format: vless://uuid@server:port?params#name
    try:
        parsed_url = urllib.parse.urlparse(link_str)
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"VLESS-Proxy-{index}"
        
        if not (uuid and server and port): # Basic validation
            print(f"[ERROR] Invalid VLESS link (missing uuid, server or port): '{link_str}'")
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        proxy_config = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "tls": False # Default to false, check security param
        }

        # TLS/Security
        if 'security' in query_params and query_params['security'][0] == 'tls':
            proxy_config['tls'] = True
            if 'sni' in query_params:
                proxy_config['sni'] = query_params['sni'][0]
            elif 'host' in query_params: # sometimes host is used as SNI
                 proxy_config['sni'] = query_params['host'][0]
            
            if 'skipCertVerify' in query_params and query_params['skipCertVerify'][0] == '1':
                proxy_config['skip-cert-verify'] = True
        
        # Transport type
        if 'type' in query_params:
            transport_type = query_params['type'][0]
            proxy_config['network'] = transport_type
            
            if transport_type == 'ws':
                proxy_config['ws-opts'] = {}
                if 'path' in query_params:
                    proxy_config['ws-opts']['path'] = query_params['path'][0]
                if 'host' in query_params:
                    # 'host' can be in query params for WS and used as header
                    proxy_config['ws-opts']['headers'] = {'Host': query_params['host'][0]}
            elif transport_type == 'grpc':
                proxy_config['grpc-opts'] = {}
                if 'serviceName' in query_params:
                    proxy_config['grpc-opts']['grpc-service-name'] = query_params['serviceName'][0]
            # Add other transport types if needed (e.g., http, tcp, kcp, quic)

        # Other VLESS parameters
        if 'flow' in query_params:
            proxy_config['flow'] = query_params['flow'][0]
        
        return proxy_config
    except Exception as e:
        print(f"[ERROR] Failed to parse VLESS link '{link_str}': {e}")
        return None

def parse_hysteria1_link(link_str, index):
    # Format: hysteria://server:port?auth=...&obfs=...&obfs-password=...&up=...&down=...#name
    try:
        # Temporarily use a dummy scheme to let urlparse handle server:port and query/fragment
        temp_link = "dummy://" + link_str[len("hysteria://"):]
        parsed_url = urllib.parse.urlparse(temp_link)
        
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"Hysteria-Proxy-{index}"
        
        if not (server and port): # Basic validation
            print(f"[ERROR] Invalid Hysteria (Hysteria1) link (missing server or port): '{link_str}'")
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        proxy_config = {
            "name": name,
            "type": "hysteria", # Hysteria1 type in Clash Meta
            "server": server,
            "port": port,
            "tls": True # Hysteria1 implies TLS
        }
        
        if 'auth' in query_params:
            proxy_config['auth'] = query_params['auth'][0]
        elif 'password' in query_params: # Some links might use 'password' for auth
            proxy_config['auth'] = query_params['password'][0]

        if 'obfs' in query_params:
            obfs_val = query_params['obfs'][0]
            if obfs_val.lower() == 'true': # Convert string "true" to boolean True
                proxy_config['obfs'] = True
            elif obfs_val.lower() == 'false':
                proxy_config['obfs'] = False
            else: # For values like 'salamander'
                proxy_config['obfs'] = obfs_val
        
        if 'obfs-password' in query_params:
            proxy_config['obfs-password'] = query_params['obfs-password'][0]
        
        if 'sni' in query_params:
            proxy_config['sni'] = query_params['sni'][0]
        if 'alpn' in query_params:
            proxy_config['alpn'] = query_params['alpn'][0].split(',')

        # Hysteria1 specific bandwidth settings - Always include 'up' and 'down' with defaults if not present
        # Use int(value) if present, else default to 100 Mbps (Clash Meta v1.19.10 seems to require them)
        try:
            proxy_config['up'] = int(query_params['up'][0]) if 'up' in query_params and query_params['up'][0].isdigit() else 100
        except ValueError:
            print(f"[WARNING] Invalid 'up' bandwidth value in Hysteria1 link: '{query_params['up'][0]}'. Defaulting to 100.")
            proxy_config['up'] = 100
        
        try:
            proxy_config['down'] = int(query_params['down'][0]) if 'down' in query_params and query_params['down'][0].isdigit() else 100
        except ValueError:
            print(f"[WARNING] Invalid 'down' bandwidth value in Hysteria1 link: '{query_params['down'][0]}'. Defaulting to 100.")
            proxy_config['down'] = 100

        if 'skipCertVerify' in query_params and query_params['skipCertVerify'][0] == '1':
            proxy_config['skip-cert-verify'] = True

        return proxy_config
    except Exception as e:
        print(f"[ERROR] Failed to parse Hysteria (Hysteria1) link '{link_str}': {e}")
        return None

def parse_hysteria2_link(link_str, index):
    # Format: hysteria2://server:port?password=...&obfs=...&obfs-password=...#name
    try:
        # Temporarily use a dummy scheme to let urlparse handle server:port and query/fragment
        temp_link = "dummy://" + link_str[len("hysteria2://"):]
        parsed_url = urllib.parse.urlparse(temp_link)
        
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"Hysteria2-Proxy-{index}"
        
        if not (server and port): # Basic validation
            print(f"[ERROR] Invalid Hysteria2 link (missing server or port): '{link_str}'")
            return None

        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        proxy_config = {
            "name": name,
            "type": "hysteria2", # Force type to hysteria2
            "server": server,
            "port": port,
            "tls": True # Hysteria2 always uses TLS
        }
        
        if 'password' in query_params:
            proxy_config['password'] = query_params['password'][0]
        if 'obfs' in query_params:
            proxy_config['obfs'] = query_params['obfs'][0]
        if 'obfs-password' in query_params:
            proxy_config['obfs-password'] = query_params['obfs-password'][0]
        if 'sni' in query_params:
            proxy_config['sni'] = query_params['sni'][0]
        if 'alpn' in query_params:
            proxy_config['alpn'] = query_params['alpn'][0].split(',')

        if 'skipCertVerify' in query_params and query_params['skipCertVerify'][0] == '1':
            proxy_config['skip-cert-verify'] = True

        return proxy_config
    except Exception as e:
        print(f"[ERROR] Failed to parse Hysteria2 link '{link_str}': {e}")
        return None


def generate_clash_config(node_links, output_path):
    """
    Generates a Clash YAML configuration file from a list of node links.
    Parses node links (ss, trojan, vless, hysteria, hysteria2) into Mihomo's YAML format.
    Ensures unique proxy names.
    """
    proxies = []
    existing_proxy_names = set() # To keep track of names already used

    for i, link in enumerate(node_links):
        parsed_proxy = None
        # Determine protocol and call appropriate parser
        if link.startswith("ss://"):
            parsed_proxy = parse_ss_link(link, i+1)
        elif link.startswith("trojan://"):
            parsed_proxy = parse_trojan_link(link, i+1)
        elif link.startswith("vless://"):
            parsed_proxy = parse_vless_link(link, i+1)
        elif link.startswith("hysteria://"): # Check Hysteria1 first
            parsed_proxy = parse_hysteria1_link(link, i+1)
        elif link.startswith("hysteria2://"): # Then Hysteria2
            parsed_proxy = parse_hysteria2_link(link, i+1)
        else:
            print(f"[WARNING] Skipping unsupported protocol or invalid link: {link}")

        if parsed_proxy:
            # --- START: Unique Name Generation Logic ---
            base_name = parsed_proxy.get('name')
            if not base_name:
                base_name = f"{parsed_proxy.get('type', 'unknown')}-proxy-{i+1}"
            
            # Clean up base_name for file system / YAML compatibility if needed
            # For now, just focus on uniqueness.
            
            unique_name = base_name
            counter = 1
            while unique_name in existing_proxy_names:
                unique_name = f"{base_name}_{counter}"
                counter += 1
            
            parsed_proxy['name'] = unique_name
            existing_proxy_names.add(unique_name)
            # --- END: Unique Name Generation Logic ---
            
            proxies.append(parsed_proxy)
        else:
            # Error message already printed by the specific parse_ function
            pass # Skip invalid or unparseable link

    if not proxies:
        print("No valid proxies generated from node links. Aborting config generation.")
        return False
    
    # --- Debugging specific proxy 11 if it exists ---
    # The "proxy 11" error corresponds to index 10 in a 0-indexed list
    if len(proxies) > 10: # Check if there's at least an 11th proxy
        print(f"\n[DEBUG] Configuration for proxy 11 (original index: {node_links.index(node_links[i-1]) + 1 if i > 0 else 'N/A'}, list index 10):")
        # Try to find the original link string for the 11th proxy if possible for better context
        # This is tricky because `proxies` list skips invalid ones. 
        # For simplicity, we print the 11th *successfully parsed* proxy.
        print(json.dumps(proxies[10], indent=2, ensure_ascii=False))
        print("-" * 30)
    # --- End Debugging ---

    # Define the structure of the Clash configuration
    clash_config = {
        "port": CLASH_PROXY_HTTP_PORT,
        "socks-port": CLASH_PROXY_HTTP_PORT + 1,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "debug", # Changed to debug for more detailed logs from Clash
        "external-controller": f"127.0.0.1:{CLASH_API_PORT}",
        "secret": "",
        "proxies": proxies, # This is now a list of dictionaries
        "proxy-groups": [
            {
                "name": "测速节点",
                "type": "select",
                "proxies": [p["name"] for p in proxies] # Use names of the parsed proxies
            }
        ],
        "rules": [
            "MATCH,测速节点"
        ]
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            # Use yaml.dump to write the dictionary as proper YAML
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, indent=2) 
        print(f"Generated Clash config at: {output_path}")
        return True
    except Exception as e:
        print(f"Failed to write Clash config: {e}")
        return False

# --- Main Logic ---

def main():
    clash_process = None

    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        os.makedirs(CLASH_BIN_DIR, exist_ok=True)

        clash_executable_path = download_and_extract_clash_core(
            CLASH_DOWNLOAD_URL, CLASH_BIN_DIR, CLASH_EXECUTABLE_NAME
        )
        if not clash_executable_path:
            print("Aborting: Could not get Clash core executable.")
            return

        print(f"Fetching node links from: {NODES_URL}")
        try:
            response = requests.get(NODES_URL, timeout=15)
            response.raise_for_status()
            raw_node_links = response.text.splitlines()
            node_links = [
                link.strip() for link in raw_node_links
                if link.strip() and not link.strip().startswith("#")
            ]
            if not node_links:
                print("No valid node links found in the remote file.")
                return
            print(f"Successfully fetched {len(node_links)} node links.")
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch node links from {NODES_URL}: {e}")
            return

        if not generate_clash_config(node_links, CLASH_CONFIG_FILE):
            print("Aborting: Could not generate Clash config.")
            return

        clash_process = start_clash(clash_executable_path, CLASH_CONFIG_FILE)
        if not clash_process:
            print("Aborting: Could not start Clash.")
            # If Clash fails to start, also try to print its log if it was created
            if os.path.exists(CLASH_LOG_FILE):
                try:
                    with open(CLASH_LOG_FILE, "r") as f:
                        print(f"Content of Clash log file ({CLASH_LOG_FILE}):")
                        for line in f.readlines()[-50:]: # Print last 50 lines
                            print(line.strip())
                except Exception as e:
                    print(f"Could not read Clash log file: {e}")
            return

        time.sleep(2) # Give Clash a moment to load proxies
        proxy_names = get_clash_proxies_names()
        if not proxy_names:
            print("No proxies found via Clash API. Check Clash config and logs.")
            return

        test_results = []
        clash_proxy_address = f"http://127.0.0.1:{CLASH_PROXY_HTTP_PORT}"
        
        print("\n--- Starting Speed Tests ---")
        for i, proxy_name in enumerate(proxy_names):
            print(f"[{i+1}/{len(proxy_names)}] Testing proxy: '{proxy_name}'...")
            
            if not set_clash_proxy_group_selection("测速节点", proxy_name):
                test_results.append(f"Proxy: {proxy_name} # 速度: 无法切换代理到 '{proxy_name}'")
                continue
            
            time.sleep(0.5) # Give Clash a moment to switch proxy

            # Pass the expected file size to the test function
            speed = test_download_speed(TEST_FILE_URL, clash_proxy_address, file_size_bytes=5 * 1024 * 1024) 
            
            if speed is not None:
                test_results.append(f"Proxy: {proxy_name} # 速度: {speed:.2f} MB/s")
                print(f"  -> Speed: {speed:.2f} MB/s")
            else:
                test_results.append(f"Proxy: {proxy_name} # 速度: 测试失败")
                print("  -> Speed: TEST FAILED")
            
            time.sleep(0.5)

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 节点测速结果 - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for result in test_results:
                f.write(result + "\n")
        print(f"\nAll test results saved to {OUTPUT_FILE}")

    finally:
        stop_clash(clash_process)
        # Always try to print the end of the Clash log file
        if os.path.exists(CLASH_LOG_FILE):
            try:
                with open(CLASH_LOG_FILE, "r") as f:
                    print(f"\n--- Clash Debug Log ({CLASH_LOG_FILE}) ---")
                    log_lines = f.readlines()
                    # Print only the last 100 lines to avoid excessively long logs
                    for line in log_lines[-100:]: 
                        print(line.strip())
                    print(f"--- End of Clash Debug Log ---")
            except Exception as e:
                print(f"Could not read Clash log file at the end: {e}")

if __name__ == "__main__":
    main()
