import requests
import os
import subprocess
import time
import datetime
import json
import shutil # For moving files
import tarfile # For tar.gz handling
import gzip # For .gz handling

# --- Configuration ---
NODES_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
OUTPUT_FILE = "data/collectSub.txt"
CLASH_CONFIG_FILE = "clash_config.yaml"
CLASH_API_PORT = 9090 # Clash external controller port
CLASH_PROXY_HTTP_PORT = 7890 # Clash HTTP proxy port
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=50000000" # Test with 50MB file. Consider a larger file (e.g., 100MB) for more accurate high-speed tests.

# Clash Meta (mihomo) Version and Download URL - Using MetaCubeX/mihomo as the original Clash is deprecated.
CLASH_VERSION_TO_DOWNLOAD = "v1.19.10" # Using the version you found
CLASH_DOWNLOAD_BASE_URL = "https://github.com/MetaCubeX/mihomo/releases/download"
CLASH_ARCHIVE_NAME = f"mihomo-linux-amd64-{CLASH_VERSION_TO_DOWNLOAD}.gz" # Using the .gz file for Linux AMD64
CLASH_DOWNLOAD_URL = f"{CLASH_DOWNLOAD_BASE_URL}/{CLASH_VERSION_TO_DOWNLOAD}/{CLASH_ARCHIVE_NAME}"

CLASH_BIN_DIR = "clash_bin" # Directory to store Clash executable (will be cached by GitHub Actions)
CLASH_EXECUTABLE_NAME = "mihomo" # Changed to 'mihomo' for Clash.Meta
CLASH_FULL_PATH = os.path.join(CLASH_BIN_DIR, CLASH_EXECUTABLE_NAME)

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

                # Prioritize exact match, then starts with
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
                extracted_name = found_paths[0] # Take the first one found
                print(f"[DEBUG] Found extracted executable at: {extracted_name}")
            else:
                print(f"[ERROR] Executable '{executable_name}' or similar not found inside .zip archive after extraction.")
                raise Exception("Executable not found inside .zip archive after extraction.")

        elif filename.endswith(".gz"):
            # This handles single gzipped executable files like mihomo-linux-amd64-vX.Y.Z.gz
            print(f"[DEBUG] Decompressing .gz file: {temp_archive_path}")
            # The decompressed file name will be temp_archive_path without .gz
            decompressed_path = os.path.join(dest_dir, executable_name) # Ensure it's decompressed directly to the target name
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

        # Ensure the executable is at the expected path (clash_exec_path)
        # This step is mostly for renaming if the extracted_name is different from executable_name
        # For .gz, we directly decompress to executable_name, so extracted_name == clash_exec_path
        if extracted_name and extracted_name != clash_exec_path:
            print(f"[DEBUG] Moving extracted executable from '{extracted_name}' to '{clash_exec_path}'...")
            shutil.move(extracted_name, clash_exec_path)
            print(f"[DEBUG] Moved successfully.")

        # Clean up temporary archive file
        print(f"[DEBUG] Removing temporary archive/file: {temp_archive_path}")
        os.remove(temp_archive_path)

        # Make executable
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
        print(f"[ERROR] An unexpected error occurred during download or extraction: {e}")
        return None

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
