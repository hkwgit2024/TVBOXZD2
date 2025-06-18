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
logging.basicConfig(filename="clash_script.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- Helper Functions ---

def get_latest_clash_version():
    try:
        response = requests.get("https://api.github.com/repos/Dreamacro/clash/releases/latest")
        response.raise_for_status()
        return response.json()['tag_name']
    except Exception as e:
        logging.error(f"Failed to fetch latest Clash version: {e}")
        return CLASH_VERSION_TO_DOWNLOAD

def check_clash_version(exec_path):
    try:
        result = subprocess.run([exec_path, "--version"], capture_output=True, text=True, check=True)
        version = result.stdout.strip().split()[-1]
        return version
    except Exception:
        return None

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def download_and_extract_clash_core(url, dest_dir, executable_name):
    """
    Downloads and extracts Clash core to dest_dir.
    Checks if the executable already exists, is executable, and matches the latest version.
    Returns path to executable or None on failure.
    """
    os.makedirs(dest_dir, exist_ok=True)
    clash_exec_path = os.path.join(dest_dir, executable_name)

    # Check if executable exists and has correct version
    latest_version = get_latest_clash_version()
    if os.path.exists(clash_exec_path) and os.path.isfile(clash_exec_path) and os.access(clash_exec_path, os.X_OK):
        current_version = check_clash_version(clash_exec_path)
        if current_version and latest_version in current_version:
            logging.info(f"Clash executable (version {current_version}) is up-to-date at {clash_exec_path}. Skipping download.")
            return clash_exec_path
        else:
            logging.info(f"Clash executable version mismatch or invalid (current: {current_version}, expected: {latest_version}). Redownloading...")

    logging.info(f"Downloading Clash core from: {url}")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        filename = url.split('/')[-1]
        temp_archive_path = os.path.join(dest_dir, filename)

        with open(temp_archive_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Downloaded Clash core archive to: {temp_archive_path}")

        # Placeholder for checksum verification (replace with actual SHA256 from release)
        # expected_sha256 = "..."  # Fetch from GitHub release
        # if not verify_clash_integrity(temp_archive_path, expected_sha256):
        #     logging.error(f"Checksum mismatch for {temp_archive_path}. Redownloading...")
        #     os.remove(temp_archive_path)
        #     return download_and_extract_clash_core(url, dest_dir, executable_name)

        extracted_name = None
        if filename.endswith(".tar.gz"):
            with tarfile.open(temp_archive_path, "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.isfile() and (m.name == executable_name or m.name.startswith(f"{executable_name}-"))]
                if not members:
                    raise Exception("Clash executable not found inside .tar.gz archive.")
                clash_member = members[0]
                tar.extract(clash_member, path=dest_dir)
                extracted_name = os.path.join(dest_dir, clash_member.name)
        elif filename.endswith(".zip"):
            subprocess.run(["unzip", "-o", temp_archive_path, "-d", dest_dir], check=True, capture_output=True, text=True)
            found_paths = []
            for root, _, files in os.walk(dest_dir):
                for f_name in files:
                    if f_name == executable_name or f_name.startswith(f"{executable_name}-") and not f_name.endswith(('.zip', '.tar.gz')):
                        found_paths.append(os.path.join(root, f_name))
            if found_paths:
                extracted_name = found_paths[0]
            else:
                raise Exception("Clash executable not found inside .zip archive after extraction.")
        else:
            raise Exception("Unsupported archive format. Only .tar.gz or .zip are supported.")

        if extracted_name and extracted_name != clash_exec_path:
            shutil.move(extracted_name, clash_exec_path)
            logging.info(f"Moved extracted Clash to: {clash_exec_path}")

        os.remove(temp_archive_path)
        subprocess.run(["chmod", "+x", clash_exec_path], check=True)
        logging.info(f"Clash executable now at: {clash_exec_path}")
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

# ... (rest of the script remains unchanged)
def generate_clash_config(node_links, output_path):
    """Generates a Clash YAML configuration file from a list of node links."""
    if not node_links:
        print("No valid node links provided to generate Clash config.")
        return False

    proxies_list_str = "\n".join([f'  - "{link}"' for link in node_links])

    # The '测速节点' (Test Node) group will be used to select individual proxies via API.
    # The 'MATCH,测速节点' rule will ensure all traffic for testing goes through this group.
    clash_config_content = f"""
port: {CLASH_PROXY_HTTP_PORT}
socks-port: {CLASH_PROXY_HTTP_PORT + 1}
allow-lan: false # Set to true if you need to access from other machines
mode: rule # Rule mode allows for custom routing
log-level: info
external-controller: 127.0.0.1:{CLASH_API_PORT}
secret: "" # No secret for local API communication (for GitHub Actions, keep it simple)

proxies:
{proxies_list_str}

proxy-groups:
  - name: "测速节点" # A selector group for our testing
    type: select
    proxies:
      - DIRECT # Default placeholder. Will be dynamically changed via API.

rules:
  - MATCH,测速节点 # Route all traffic through our testing group
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
        # Use subprocess.Popen for non-blocking start
        process = subprocess.Popen(
            [clash_executable_path, "-f", config_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True # Decode stdout/stderr as text
        )
        
        # Give Clash some initial time to start up
        time.sleep(3) 

        # Check if Clash process exited prematurely
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"Clash exited prematurely. Stdout:\n{stdout}\nStderr:\n{stderr}")
            return None # Clash failed to start
        
        print(f"Clash started (PID: {process.pid}). Waiting for API to become available...")
        
        # Verify Clash API is reachable
        api_url = f"http://127.0.0.1:{CLASH_API_PORT}/configs"
        for i in range(15): # Retry up to 15 times (max 30 seconds wait)
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
    if clash_process and clash_process.poll() is None: # If process is still running
        print("Stopping Clash process...")
        try:
            clash_process.terminate() # Send SIGTERM
            clash_process.wait(timeout=5) # Wait for it to terminate
        except subprocess.TimeoutExpired:
            print("Clash did not terminate gracefully, sending SIGKILL.")
            clash_process.kill() # Force kill
            clash_process.wait(timeout=5)
        print("Clash process stopped.")
    else:
        print("Clash process was not running or already stopped.")

def get_clash_proxies_names():
    """Fetches all available proxy names from Clash API."""
    api_url = f"http://127.0.0.1:{CLASH_API_PORT}/proxies"
    try:
        response = requests.get(api_url, timeout=10) # Increased timeout for API calls
        response.raise_for_status()
        data = response.json()
        
        # Filter out proxy groups and internal proxies (like 'DIRECT', 'REJECT')
        # We want the names of the actual proxy nodes loaded from the config.
        # Clash's /proxies endpoint lists both individual proxies and proxy groups.
        # Individual proxies usually have type like 'Shadowsocks', 'Vmess', 'Trojan', etc.
        # Proxy groups have type 'Selector', 'URLTest', 'Fallback'.
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
        # Use stream=True to handle large files efficiently
        # Add headers to request a specific byte range to ensure the server
        # sends at least the desired amount of data, if it supports Range requests.
        # However, for Cloudflare's __down endpoint, it's already size-controlled.
        # headers = {"Range": f"bytes=0-{file_size_bytes-1}"}
        response = requests.get(url, proxies=proxies, stream=True, timeout=60) # Increased timeout for download
        response.raise_for_status() # Raise an exception for bad status codes

        for chunk in response.iter_content(chunk_size=8192): # Iterate in chunks
            if chunk:
                downloaded_bytes += len(chunk)
                if downloaded_bytes >= file_size_bytes: # Stop once desired size is reached
                    break
        
        end_time = time.time()
        duration = end_time - start_time

        if duration > 0 and downloaded_bytes > 0:
            speed_mb_s = (downloaded_bytes / (1024 * 1024)) / duration # MB/s
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
    except requests.exceptions.RequestException as e: # Catch all other requests-related errors
        print(f"下载失败 (通过 {proxy_address}): {e}")
        return None
    except Exception as e:
        print(f"发生未知错误 during speed test: {e}")
        return None

# --- Main Logic ---

def main():
    clash_process = None # Initialize clash_process to None

    try:
        # 1. Create data directory for output
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        # Create Clash bin directory if not exists
        os.makedirs(CLASH_BIN_DIR, exist_ok=True)

        # 2. Download and extract Clash core (will use cached if available)
        clash_executable_path = download_and_extract_clash_core(
            CLASH_DOWNLOAD_URL, CLASH_BIN_DIR, CLASH_EXECUTABLE_NAME
        )
        if not clash_executable_path:
            print("Aborting: Could not get Clash core executable.")
            return

        # 3. Fetch node links from the remote URL
        print(f"Fetching node links from: {NODES_URL}")
        try:
            response = requests.get(NODES_URL, timeout=15) # Increased timeout for fetching nodes
            response.raise_for_status()
            raw_node_links = response.text.splitlines()
            # Filter out empty lines, comments, and strip whitespace
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

        # 4. Generate Clash YAML configuration
        if not generate_clash_config(node_links, CLASH_CONFIG_FILE):
            print("Aborting: Could not generate Clash config.")
            return

        # 5. Start Clash
        clash_process = start_clash(clash_executable_path, CLASH_CONFIG_FILE)
        if not clash_process:
            print("Aborting: Could not start Clash.")
            return

        # 6. Get proxy names from Clash API
        # Give Clash a moment to fully parse proxies after startup
        time.sleep(2) 
        proxy_names = get_clash_proxies_names()
        if not proxy_names:
            print("No proxies found via Clash API. Check Clash config and logs.")
            return

        # 7. Perform speed tests for each node
        test_results = []
        clash_proxy_address = f"http://127.0.0.1:{CLASH_PROXY_HTTP_PORT}"
        
        print("\n--- Starting Speed Tests ---")
        for i, proxy_name in enumerate(proxy_names):
            # Attempt to find the original link for better context in output
            # This is a heuristic as Clash's internal proxy names might not directly map to original links
            # if the link itself doesn't contain a name.
            # A more robust solution would involve parsing the name from the link during config generation
            # and mapping it. For now, we'll try to use the corresponding original link by index.
            original_link_for_output = node_links[i] if i < len(node_links) else "Unknown Original Link"

            print(f"[{i+1}/{len(proxy_names)}] Testing Clash-assigned proxy name: '{proxy_name}' (Original Link: {original_link_for_output})...")
            
            # Set the "测速节点" (Test Node) proxy group to use the current proxy
            if not set_clash_proxy_group_selection("测速节点", proxy_name):
                test_results.append(f"{original_link_for_output} # 速度: 无法切换代理到 '{proxy_name}'")
                continue
            
            # Give Clash a small moment to apply the proxy switch
            time.sleep(0.5)

            # Perform the download test
            speed = test_download_speed(TEST_FILE_URL, clash_proxy_address, file_size_bytes=50 * 1024 * 1024)
            
            if speed is not None:
                test_results.append(f"{original_link_for_output} # 速度: {speed:.2f} MB/s")
                print(f"  -> Speed: {speed:.2f} MB/s")
            else:
                test_results.append(f"{original_link_for_output} # 速度: 测试失败")
                print("  -> Speed: TEST FAILED")
            
            # Add a small delay between tests to be gentle on resources and APIs
            time.sleep(0.5)

        # 8. Save test results to file
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(f"# 节点测速结果 - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for result in test_results:
                f.write(result + "\n")
        print(f"\nAll test results saved to {OUTPUT_FILE}")

    finally:
        # Ensure Clash process is stopped even if errors occur
        stop_clash(clash_process)

if __name__ == "__main__":
    main()
