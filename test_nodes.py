import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
from typing import Dict, List
from yaml import SafeLoader

# --- Constants ---
CLASH_PORT = 7890
CLASH_SOCKS_PORT = 7891
CLASH_API_PORT = 9090 # Clash/Mihomo 默认的 RESTful API 端口
CLASH_BIN_PATH = './tools/clash'
TEMP_DIR = 'temp'
DATA_DIR = 'data'
CONFIG_BASE_PATH = os.path.join(TEMP_DIR, 'clash_base_config.yaml')

# --- Custom YAML constructor ---
def str_constructor(loader, node):
    return str(node.value)

SafeLoader.add_constructor('!str', str_constructor)

# --- Proxy Validation Function ---
def validate_proxy(proxy: Dict, index: int) -> tuple[bool, str]:
    """Validates the proxy node format, returns (is_valid, error_message)"""
    required_fields = {
        'name': str,
        'server': str,
        'port': int,
        'type': str
    }
    protocol_specific_fields = {
        'trojan': [('password', str)],
        'vmess': [('uuid', str)],
        'vless': [('uuid', str)],
        'ss': [('cipher', str), ('password', str)],
        'hysteria2': [('password', str)]
    }

    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"Node {index} is missing field: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"Node {index} field {field} has wrong type, expected {field_type.__name__}, got {type(proxy[field]).__name__}"

    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"Node {index} ({proxy_type}) is missing field: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"Node {index} ({proxy_type}) field {field} has wrong type, expected {field_type.__name__}, got {type(proxy[field]).__name__}"

    if not proxy['name'].strip():
        return False, f"Node {index} name is empty"

    return True, ""

# --- Helper to start Clash/Mihomo core ---
async def start_clash_core(proxies: List[Dict]) -> subprocess.Popen:
    """
    Starts a single Clash/Mihomo core instance with all proxies loaded.
    Returns the subprocess Popen object if successful, else raises an exception.
    """
    print("Attempting to start Clash/Mihomo core...")
    
    # Write a base config with all proxies, but initially use a 'direct' group for API access
    base_config = {
        'port': CLASH_PORT,
        'socks-port': CLASH_SOCKS_PORT,
        'allow-lan': False, # For security in CI
        'mode': 'direct', # Start in direct mode to ensure API is reachable first
        'log-level': 'info', # More verbose logs for debugging
        'external-controller': f'127.0.0.1:{CLASH_API_PORT}',
        'secret': '', # Can add a secret if needed, but for local testing, keep empty
        'proxies': proxies,
        'proxy-groups': [
            {'name': 'GLOBAL', 'type': 'select', 'proxies': [p['name'] for p in proxies]},
            {'name': 'DIRECT', 'type': 'direct'} # Add a direct group for initial API check
        ],
        'rules': [
            'MATCH,GLOBAL'
        ]
    }
    
    os.makedirs(TEMP_DIR, exist_ok=True)
    try:
        with open(CONFIG_BASE_PATH, 'w') as f:
            yaml.dump(base_config, f, allow_unicode=True, indent=2)
        print(f"Base config written to {CONFIG_BASE_PATH}")
    except Exception as e:
        raise RuntimeError(f"Failed to write base Clash/Mihomo config: {e}")

    # Start Clash/Mihomo
    # Redirect stdout/stderr to files for debugging, rather than DEVNULL
    clash_stdout_log = os.path.join(TEMP_DIR, 'clash_stdout.log')
    clash_stderr_log = os.path.join(TEMP_DIR, 'clash_stderr.log')
    
    stdout_file = open(clash_stdout_log, 'w')
    stderr_file = open(clash_stderr_log, 'w')

    proc = None
    max_startup_attempts = 5
    startup_delay_seconds = 3 # Initial delay
    
    for attempt in range(max_startup_attempts):
        print(f"Starting Clash/Mihomo core (Attempt {attempt + 1}/{max_startup_attempts})...")
        proc = subprocess.Popen(
            [CLASH_BIN_PATH, '-f', CONFIG_BASE_PATH, '-d', TEMP_DIR],
            stdout=stdout_file, # Redirect stdout to file
            stderr=stderr_file  # Redirect stderr to file
        )
        await asyncio.sleep(startup_delay_seconds) # Wait for core to start

        # Check API health
        try:
            api_url = f'http://127.0.0.1:{CLASH_API_PORT}/proxies'
            async with aiohttp.ClientSession() as s:
                async with s.get(api_url, timeout=5) as response:
                    if response.status == 200:
                        print("Clash/Mihomo core API is reachable.")
                        # Check if it returns expected data (optional, but good for validation)
                        data = await response.json()
                        if 'proxies' in data:
                            print("Clash/Mihomo core started successfully and returned proxy list.")
                            return proc # Return the process object
                        else:
                            print("Clash/Mihomo API reachable but returned unexpected data.")
                    else:
                        print(f"Clash/Mihomo API responded with status {response.status}.")
                        if response.status == 400: # Specific error, might indicate config issue
                            print("Error 400 likely indicates a bad configuration or API misusage.")
                            print(f"Clash stdout: {open(clash_stdout_log).read()}")
                            print(f"Clash stderr: {open(clash_stderr_log).read()}")
        except aiohttp.ClientConnectorError as e:
            print(f"Clash/Mihomo API connection failed: {e}")
        except asyncio.TimeoutError:
            print("Clash/Mihomo API health check timed out.")
        except Exception as e:
            print(f"An unexpected error occurred during API health check: {e}")
        
        # If connection or response failed, terminate and retry
        if proc:
            proc.terminate()
            await asyncio.sleep(1) # Give it a moment to terminate
            if proc.poll() is None: # If still running
                proc.kill()
            await asyncio.sleep(1) # Extra wait before next attempt
        
        startup_delay_seconds += 2 # Increase delay for next attempt

    stdout_file.close()
    stderr_file.close()
    raise RuntimeError("Failed to start Clash/Mihomo core after multiple attempts. Check logs in 'temp/' directory for details.")

# --- Test single proxy using Clash API ---
async def test_proxy_via_api(
    proxy_name: str, 
    session: aiohttp.ClientSession, 
    clash_api_port: int = CLASH_API_PORT
) -> Dict:
    """
    Tests a single proxy node by switching via Clash API and using its built-in latency test.
    """
    print(f"Testing proxy node: {proxy_name}")
    api_base_url = f'http://127.0.0.1:{clash_api_port}'
    
    result = {'name': proxy_name, 'status': 'Unavailable', 'latency': None, 'error': None}
    
    # 1. Switch active proxy in Clash/Mihomo
    try:
        set_proxy_url = f"{api_base_url}/proxies/GLOBAL"
        async with session.put(set_proxy_url, json={'name': proxy_name}, timeout=5) as response:
            if response.status != 204: # 204 No Content is expected for successful change
                error_msg = await response.text()
                result['error'] = f"Failed to switch proxy via API ({response.status}): {error_msg[:100]}"
                print(f"  {proxy_name}: {result['error']}")
                return result
    except Exception as e:
        result['error'] = f"Error switching proxy via API: {e}"
        print(f"  {proxy_name}: {result['error']}")
        return result

    # 2. Use Clash/Mihomo's built-in latency test
    max_test_retries = 2
    test_timeout = 15 # Seconds, this is for the API call itself, not the proxy test duration
    
    for attempt in range(max_test_retries):
        try:
            delay_test_url = f"{api_base_url}/proxies/{proxy_name}/delay?url=http://www.gstatic.com/generate_204&timeout=5000"
            # timeout=5000ms is for the internal test in Clash/Mihomo
            async with session.get(delay_test_url, timeout=test_timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    latency = data.get('delay')
                    if latency is not None:
                        result['status'] = 'Available'
                        result['latency'] = latency
                        break # Success
                    else:
                        result['error'] = f"API returned no delay for {proxy_name}"
                else:
                    error_msg = await response.text()
                    result['error'] = f"API delay test failed for {proxy_name} ({response.status}): {error_msg[:100]}"
        except Exception as e:
            result['error'] = f"Error during API delay test for {proxy_name} (Attempt {attempt + 1}/{max_test_retries}): {e}"
        
        if result['status'] == 'Available':
            break
        elif attempt < max_test_retries - 1:
            await asyncio.sleep(5) # Wait before retry

    if result['status'] == 'Unavailable' and not result['error']:
        result['error'] = "Proxy did not become available after tests."
        
    print(f"  {proxy_name}: {result['status']}{f' (Latency: {result["latency"]:.2f}ms)' if result['latency'] else ''}{f' Error: {result["error"]}' if result['error'] else ''}")
    return result

# --- Main function ---
async def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    # Read 520.yaml
    try:
        with open(os.path.join(DATA_DIR, '520.yaml'), 'r') as f:
            config = yaml.load(f, Loader=SafeLoader)
        proxies = config.get('proxies', [])
    except yaml.YAMLError as e:
        print(f"Failed to parse 520.yaml: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read 520.yaml: {e}")
        sys.exit(1)

    if not proxies:
        print("No proxy nodes found in 520.yaml")
        sys.exit(1)

    # Validate node format
    valid_proxies = []
    invalid_proxies_format = []
    for i, proxy in enumerate(proxies):
        is_valid, error = validate_proxy(proxy, i)
        if is_valid:
            valid_proxies.append(proxy)
        else:
            invalid_proxies_format.append({'name': proxy.get('name', f'Node_{i}'), 'error': error})

    # Record format invalid nodes
    if invalid_proxies_format:
        print(f"Found {len(invalid_proxies_format)} nodes with invalid format.")
        with open(os.path.join(DATA_DIR, 'invalid_nodes_format.yaml'), 'w') as f:
            yaml.dump({'invalid_proxies': invalid_proxies_format}, f, allow_unicode=True, indent=2)
        print(f"Details for format issues in {os.path.join(DATA_DIR, 'invalid_nodes_format.yaml')}")
        # Only test nodes with valid format
        proxies_to_test = [p for p in valid_proxies]
    else:
        proxies_to_test = valid_proxies
    
    if not proxies_to_test:
        print("No valid proxy nodes to test after format validation.")
        sys.exit(0) # Exit successfully if no valid nodes to test

    clash_process = None
    all_test_results = []
    
    try:
        clash_process = await start_clash_core(proxies_to_test)
        
        async with aiohttp.ClientSession() as session:
            # Control concurrency for API calls
            semaphore = asyncio.Semaphore(5) # Limit concurrent API tests to 5

            tasks = []
            for proxy in proxies_to_test:
                async def limited_test():
                    async with semaphore:
                        return await test_proxy_via_api(proxy['name'], session)
                tasks.append(limited_test())
            
            # Use asyncio.as_completed for results as they finish
            for i, future in enumerate(asyncio.as_completed(tasks)):
                result = await future
                all_test_results.append(result)
                print(f"[{i+1}/{len(proxies_to_test)}] {result['name']}: {result['status']}{f' (Latency: {result["latency"]:.2f}ms)' if result['latency'] else ''}{f' Error: {result["error"]}' if result['error'] else ''}")

    except RuntimeError as e:
        print(f"Critical error: {e}")
        sys.exit(1)
    finally:
        if clash_process:
            print("Terminating Clash/Mihomo core.")
            clash_process.terminate()
            await asyncio.sleep(2)
            if clash_process.poll() is None: # If still running
                clash_process.kill()
            # Close redirected log files
            if stdout_file: stdout_file.close()
            if stderr_file: stderr_file.close()

        # Final cleanup of temp directory
        try:
            import shutil
            shutil.rmtree(TEMP_DIR, ignore_errors=True)
            print(f"Cleaned up {TEMP_DIR} directory.")
        except Exception as e:
            print(f"Error cleaning up temp directory: {e}")

    # Write final results
    valid_results = [r for r in all_test_results if r['status'] == 'Available']
    invalid_test_results = [r for r in all_test_results if r['status'] == 'Unavailable']

    with open(os.path.join(DATA_DIR, '521.yaml'), 'w') as f:
        yaml.dump({'results': valid_results}, f, allow_unicode=True, indent=2)
    print(f"\nFound {len(valid_results)} available nodes. See {os.path.join(DATA_DIR, '521.yaml')}")

    if invalid_test_results:
        with open(os.path.join(DATA_DIR, 'invalid_nodes.yaml'), 'w') as f:
            yaml.dump({'invalid_proxies': invalid_test_results}, f, allow_unicode=True, indent=2)
        print(f"Found {len(invalid_test_results)} unavailable nodes after testing. Details in {os.path.join(DATA_DIR, 'invalid_nodes.yaml')}")
        # Exit with error if there are unavailable nodes, to signal workflow failure
        sys.exit(1)
    else:
        print("All valid nodes are available.")
        sys.exit(0) # Exit successfully

if __name__ == "__main__":
    # Ensure a clean slate for logs
    if os.path.exists(TEMP_DIR):
        import shutil
        shutil.rmtree(TEMP_DIR)
    
    # Store stdout/stderr file objects globally to ensure closure in finally block
    stdout_file = None
    stderr_file = None

    asyncio.run(main())
