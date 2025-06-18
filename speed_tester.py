
import requests
import os
import subprocess
import time
import datetime
import json
import shutil
import tarfile
import hashlib
import platform
import logging

# --- Configuration ---
NODES_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
OUTPUT_FILE = "data/collectSub.txt"
CLASH_CONFIG_FILE = "clash_config.yaml"
CLASH_API_PORT = 9090
CLASH_PROXY_HTTP_PORT = 7890
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=50000000"
CLASH_VERSION_TO_DOWNLOAD = "v1.18.0"
CLASH_DOWNLOAD_BASE_URL = "https://github.com/Dreamacro/clash/releases/download"
CLASH_ARCHIVE_NAME = f"clash-linux-amd64-{CLASH_VERSION_TO_DOWNLOAD}.tar.gz"
CLASH_DOWNLOAD_URL = f"{CLASH_DOWNLOAD_BASE_URL}/{CLASH_VERSION_TO_DOWNLOAD}/{CLASH_ARCHIVE_NAME}"
CLASH_BIN_DIR = "clash_bin"
CLASH_EXECUTABLE_NAME = "clash"
CLASH_FULL_PATH = os.path.join(CLASH_BIN_DIR, CLASH_EXECUTABLE_NAME)

# Setup logging
logging.basicConfig(
    filename="clash_script.log",
    level=logging.DEBUG,  # Change to DEBUG for more detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- Helper Functions ---

def get_latest_clash_version():
    logging.debug("Fetching latest Clash version from GitHub API")
    try:
        response = requests.get("https://api.github.com/repos/Dreamacro/clash/releases/latest", timeout=10)
        response.raise_for_status()
        version = response.json()['tag_name']
        logging.info(f"Latest Clash version: {version}")
        return version
    except Exception as e:
        logging.error(f"Failed to fetch latest Clash version: {e}")
        return CLASH_VERSION_TO_DOWNLOAD

def check_clash_version(exec_path):
    logging.debug(f"Checking Clash version for {exec_path}")
    try:
        result = subprocess.run([exec_path, "--version"], capture_output=True, text=True, check=True)
        version = result.stdout.strip().split()[-1]
        logging.info(f"Clash version: {version}")
        return version
    except Exception as e:
        logging.error(f"Failed to check Clash version: {e}")
        return None

def calculate_sha256(file_path):
    logging.debug(f"Calculating SHA256 for {file_path}")
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        checksum = sha256.hexdigest()
        logging.info(f"SHA256 for {file_path}: {checksum}")
        return checksum
    except Exception as e:
        logging.error(f"Failed to calculate SHA256 for {file_path}: {e}")
        return None

def download_and_extract_clash_core(url, dest_dir, executable_name):
    """
    Downloads and extracts Clash core to dest_dir.
    Checks if the executable already exists, is executable, and matches the latest version.
    Returns path to executable or None on failure.
    """
    logging.info(f"Starting download and extraction for Clash core. URL: {url}, Dest: {dest_dir}")
    os.makedirs(dest_dir, exist_ok=True)
    clash_exec_path = os.path.join(dest_dir, executable_name)

    # Check if executable exists and is valid
    latest_version = get_latest_clash_version()
    if os.path.exists(clash_exec_path) and os.path.isfile(clash_exec_path) and os.access(clash_exec_path, os.X_OK):
        current_version = check_clash_version(clash_exec_path)
        if current_version and latest_version in current_version:
            logging.info(f"Valid Clash executable (version {current_version}) found at {clash_exec_path}. Skipping download.")
            return clash_exec_path
        else:
            logging.warning(f"Clash executable invalid or version mismatch (current: {current_version}, expected: {latest_version}). Removing and redownloading.")
            try:
                os.remove(clash_exec_path)
                logging.info(f"Removed invalid Clash executable: {clash_exec_path}")
            except Exception as e:
                logging.error(f"Failed to remove invalid Clash executable: {e}")

    logging.info(f"Downloading Clash core from: {url}")
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        filename = url.split('/')[-1]
        temp_archive_path = os.path.join(dest_dir, filename)

        logging.debug(f"Saving downloaded archive to: {temp_archive_path}")
        with open(temp_archive_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded Clash core archive to: {temp_archive_path}")

        # Optional: Verify checksum (requires SHA256 from GitHub release)
        # expected_sha256 = "..."  # Replace with actual SHA256
        # if expected_sha256 and calculate_sha256(temp_archive_path) != expected_sha256:
        #     logging.error(f"Checksum mismatch for {temp_archive_path}. Redownloading...")
        #     os.remove(temp_archive_path)
        #     return download_and_extract_clash_core(url, dest_dir, executable_name)

        logging.debug(f"Extracting archive: {temp_archive_path}")
        extracted_name = None
        if filename.endswith(".tar.gz"):
            with tarfile.open(temp_archive_path, "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.isfile() and (m.name == executable_name or m.name.startswith(f"{executable_name}-"))]
                if not members:
                    logging.error("Clash executable not found inside .tar.gz archive.")
                    raise Exception("Clash executable not found inside .tar.gz archive.")
                clash_member = members[0]
                logging.debug(f"Found Clash executable in archive: {clash_member.name}")
                tar.extract(clash_member, path=dest_dir)
                extracted_name = os.path.join(dest_dir, clash_member.name)
        elif filename.endswith(".zip"):
            logging.debug("Extracting .zip archive using unzip")
            result = subprocess.run(["unzip", "-o", temp_archive_path, "-d", dest_dir], capture_output=True, text=True, check=True)
            logging.debug(f"Unzip output: {result.stdout}")
            found_paths = []
            for root, _, files in os.walk(dest_dir):
                for f_name in files:
                    if f_name == executable_name or f_name.startswith(f"{executable_name}-") and not f_name.endswith(('.zip', '.tar.gz')):
                        found_paths.append(os.path.join(root, f_name))
            if found_paths:
                extracted_name = found_paths[0]
                logging.info(f"Found Clash executable in .zip: {extracted_name}")
            else:
                logging.error("Clash executable not found inside .zip archive after extraction.")
                raise Exception("Clash executable not found inside .zip archive after extraction.")
        else:
            logging.error(f"Unsupported archive format: {filename}. Only .tar.gz or .zip are supported.")
            raise Exception("Unsupported archive format. Only .tar.gz or .zip are supported.")

        if extracted_name and extracted_name != clash_exec_path:
            logging.debug(f"Moving extracted Clash from {extracted_name} to {clash_exec_path}")
            shutil.move(extracted_name, clash_exec_path)
            logging.info(f"Moved extracted Clash to: {clash_exec_path}")

        logging.debug(f"Removing temporary archive: {temp_archive_path}")
        os.remove(temp_archive_path)

        logging.debug(f"Setting executable permissions for: {clash_exec_path}")
        subprocess.run(["chmod", "+x", clash_exec_path], check=True, capture_output=True, text=True)
        logging.info(f"Clash executable ready at: {clash_exec_path}")
        return clash_exec_path
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error during Clash download: {e}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Extraction failed: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"Failed to download or extract Clash core: {e}")
        return None

# ... (rest of the script remains unchanged, included for completeness)
def generate_clash_config(node_links, output_path):
    """Generates a Clash YAML configuration file from a list of node links."""
    if not node_links:
        print("No valid node links provided to generate Clash config.")
        return False

    proxies_list_str = "\n".join([f'  - "{link}"' for link in node_links])

    clash_config_content = f"""
port: {CLASH_PROXY_HTTP_PORT}
socks-port: {CLASH_PROXY_HTTP_PORT + 1}
allow-lan: false
mode: rule
log-level: info
external-controller: 127.0.0.1:{CLASH_API_PORT}
secret: ""

proxies:
{proxies_list_str}

proxy-groups:
  - name: "测速节点"
    type: select
    proxies:
      - DIRECT

rules:
  - MATCH,测速节点
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(clash_config_content.strip())
        print(f"Generated Clash config at: {output_path}")
        return True
    except Exception as e:
        print(f"Failed to write Clash config: {e}")
        return False

def start_clash(clash_executable_path, config_file_path):
    """Starts Clash in the background and verifies API availability."""
    try:
        print(f"Starting Clash from {clash_executable_path} with config {config_file_path}...")
        process = subprocess.Popen(
            [clash_executable_path, "-f", config_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(3)

        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"Clash exited prematurely. Stdout:\n{stdout}\nStderr:\n{stderr}")
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
        print(f"Clash proxy group '{group_name}' set to '{proxy_name}'.")
        return True
    except Exception as e:
        print(f"Failed to set Clash proxy group selection for '{group_name}' to '{proxy_name}': {e}")
        return False

def test_download_speed(url, proxy_address, file_size_bytes=50 * 1024 * 1024):
    """Tests download speed using the specified proxy."""
    proxies = {
        "http": proxy_address,
        "https": proxy_address,
    }
    
    start_time = time.time()
    downloaded_bytes = 0
    try:
        response = requests.get(url, proxies=proxies, stream=True, timeout=60)
        response.raise_for_status()

        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= file_size_bytes:
                    break
        
        end_time = time.time()
        duration = end_time - start_time

        if duration > 0 and downloaded_bytes > 0:
            speed_mb_s = (downloaded_bytes / (1024 * 1024)) / duration
            return speed_mb_s
        else:
            print(f"No data downloaded or zero duration for {url}")
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
            return

        time.sleep(2)
        proxy_names = get_clash_proxies_names()
        if not proxy_names:
            print("No proxies found via Clash API. Check Clash config and logs.")
            return

        test_results = []
        clash_proxy_address = f"http://127.0.0.1:{CLASH_PROXY_HTTP_PORT}"
        
        print("\n--- Starting Speed Tests ---")
        for i, proxy_name in enumerate(proxy_names):
            original_link_for_output = node_links[i] if i < len(node_links) else "Unknown Original Link"
            print(f"[{i+1}/{len(proxy_names)}] Testing Clash-assigned proxy name: '{proxy_name}' (Original Link: {original_link_for_output})...")
            
            if not set_clash_proxy_group_selection("测速节点", proxy_name):
                test_results.append(f"{original_link_for_output} # 速度: 无法切换代理到 '{proxy_name}'")
                continue
            
            time.sleep(0.5)
            speed = test_download_speed(TEST_FILE_URL, clash_proxy_address, file_size_bytes=50 * 1024 * 1024)
            
            if speed is not None:
                test_results.append(f"{original_link_for_output} # 速度: {speed:.2f} MB/s")
                print(f"  -> Speed: {speed:.2f} MB/s")
            else:
                test_results.append(f"{original_link_for_output} # 速度: 测试失败")
                print("  -> Speed: TEST FAILED")
            
            time.sleep(0.5)

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 节点测速结果 - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for result in test_results:
                f.write(result + "\n")
        print(f"\nAll test results saved to {OUTPUT_FILE}")

    finally:
        stop_clash(clash_process)

if __name__ == "__main__":
    main()
