import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
from typing import Dict, List
from yaml import SafeLoader

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

    # Check required fields
    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"Node {index} is missing field: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"Node {index} field {field} has wrong type, expected {field_type.__name__}, got {type(proxy[field]).__name__}"

    # Check protocol-specific fields
    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"Node {index} ({proxy_type}) is missing field: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"Node {index} ({proxy_type}) field {field} has wrong type, expected {field_type.__name__}, got {type(proxy[field]).__name__}"

    # Check name uniqueness (simple check, actual check should be global)
    if not proxy['name'].strip():
        return False, f"Node {index} name is empty"

    return True, ""

# --- Test Proxy Node Function ---
async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    """Tests a single proxy node, returns the result"""
    proxy_name = proxy.get('name', 'unknown')
    print(f"Testing proxy node: {proxy_name}")

    # Write temporary Clash configuration file
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'mode': 'global',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy_name]}],
        'rules': ['MATCH,auto']
    }
    os.makedirs('temp', exist_ok=True)
    config_path = f'temp/config_{proxy_name}.yaml'
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        return {'name': proxy_name, 'status': 'Unavailable', 'latency': None, 'error': f"Failed to write config: {str(e)}"}

    proc = None # Initialize process variable
    result = {'name': proxy_name, 'status': 'Unavailable', 'latency': None, 'error': None}
    
    # --- Increase Clash/Mihomo startup attempts and health checks ---
    max_clash_startup_retries = 3
    clash_startup_delay = 5 # Wait time for each startup attempt
    clash_api_url = f'http://127.0.0.1:{clash_port}/proxies' # Clash/Mihomo API for health check

    for attempt in range(max_clash_startup_retries):
        proc = subprocess.Popen([clash_bin, '-f', config_path, '-d', 'temp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # '-d temp' parameter makes Clash/Mihomo put logs and cache in the temp directory, keeping the main directory clean
        
        await asyncio.sleep(clash_startup_delay) # Extend waiting time

        # Try to connect to the API port for a health check
        try:
            async with session.get(clash_api_url, timeout=3) as api_response:
                if api_response.status == 200:
                    # API is reachable, indicating Clash/Mihomo has started
                    print(f"  {proxy_name}: Clash/Mihomo core started successfully (Attempt {attempt + 1}/{max_clash_startup_retries})")
                    break # Successfully started, exit retry loop
                else:
                    print(f"  {proxy_name}: Clash/Mihomo API response error {api_response.status} (Attempt {attempt + 1}/{max_clash_startup_retries})")
        except Exception as e:
            print(f"  {proxy_name}: Clash/Mihomo API connection failed: {e} (Attempt {attempt + 1}/{max_clash_startup_retries})")
        
        # If current attempt fails, terminate old process and prepare for next attempt
        if proc:
            proc.terminate()
            await asyncio.sleep(1) # Give process some time to terminate
            proc.kill() # Ensure process is killed
            await asyncio.sleep(0.5)

    if proc is None or proc.poll() is not None: # If process did not start or already terminated
        return {'name': proxy_name, 'status': 'Unavailable', 'latency': None, 'error': "Clash/Mihomo core failed to start"}

    # --- Add testing retry mechanism ---
    max_test_retries = 2
    test_timeout = 10 # Extend testing timeout
    success = False

    # Main try block for the actual proxy testing logic
    try: 
        for attempt in range(max_test_retries):
            try:
                start_time = time.time()
                # Prefer testing HTTP proxy
                async with session.get(
                    'http://www.google.com/generate_204', # Use a lightweight and stable test URL
                    proxy=f'http://127.0.0.1:{clash_port}',
                    timeout=test_timeout
                ) as response:
                    if response.status == 204: # google.com/generate_204 returns 204 No Content
                        result['status'] = 'Available'
                        result['latency'] = (time.time() - start_time) * 1000  # Milliseconds
                        success = True
                        break
            except Exception as e:
                # If HTTP test fails, try SOCKS5
                try:
                    start_time_socks5 = time.time() # Reset timer for SOCKS5
                    async with session.get(
                        'http://www.google.com/generate_204',
                        proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                        timeout=test_timeout
                    ) as response:
                        if response.status == 204:
                            result['status'] = 'Available'
                            result['latency'] = (time.time() - start_time_socks5) * 1000  # Milliseconds
                            success = True
                            break
                except Exception as socks5_e:
                    result['error'] = f"Test failed (Attempt {attempt + 1}/{max_test_retries}): HTTP ({e}) / SOCKS5 ({socks5_e})"
                    if attempt < max_test_retries - 1:
                        await asyncio.sleep(5) # Wait a bit before retrying after failure
                    continue # Continue to the next retry loop
            
            if success:
                break # If test successful, exit retry loop
    finally: # This finally block is correctly associated with the main try block above
        # --- Clean up Clash/Mihomo process and files ---
        if proc:
            try:
                proc.terminate()
                await asyncio.sleep(1)
                if proc.poll() is None: # If process is still running, force kill
                    proc.kill()
            except ProcessLookupError:
                pass # Process might have already ended

        try:
            os.remove(config_path)
            # Clean up extra files generated by Clash/Mihomo in the temp directory (like geoip.dat etc.)
            for f in os.listdir('temp'):
                if f.startswith(f"config_{proxy_name}") or f.endswith(".dat"): # More precise cleanup rules
                    try:
                        os.remove(os.path.join('temp', f))
                    except OSError:
                        pass # File might not exist or be in use
        except OSError:
            pass # File might not exist

    return result

# --- Main function ---
async def main():
    # Read 520.yaml
    try:
        with open('data/520.yaml', 'r') as f:
            config = yaml.load(f, Loader=SafeLoader)
        proxies = config.get('proxies', [])
    except yaml.YAMLError as e:
        print(f"Failed to parse 520.yaml: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read 520.yaml: {str(e)}")
        sys.exit(1)

    if not proxies:
        print("No proxy nodes found")
        sys.exit(1)

    # Validate node format
    valid_proxies = []
    invalid_proxies = []
    for i, proxy in enumerate(proxies):
        is_valid, error = validate_proxy(proxy, i)
        if is_valid:
            valid_proxies.append(proxy)
        else:
            invalid_proxies.append({'name': proxy.get('name', f'Node_{i}'), 'error': error})

    # Log invalid nodes
    if invalid_proxies:
        with open('data/invalid_nodes.yaml', 'w') as f:
            yaml.dump({'invalid_proxies': invalid_proxies}, f, allow_unicode=True)
        print(f"Found {len(invalid_proxies)} invalid nodes, see data/invalid_nodes.yaml for details")

    # Create output file
    os.makedirs('data', exist_ok=True)
    with open('data/521.yaml', 'w') as f:
        f.write('results:\n')

    # Configure aiohttp session
    async with aiohttp.ClientSession() as session:
        # Batch concurrent testing (50 nodes per batch)
        # Note: batch_size = 50 here means launching 50 Clash/Mihomo instances simultaneously.
        # On GitHub Actions, this might put significant pressure on resources.
        # If instability persists, consider lowering batch_size, e.g., 10-20.
        batch_size = 20 # Lower batch size to reduce concurrent instances
        
        # Use asyncio.Semaphore to further control concurrency, even with a larger batch_size
        # For example, limit to no more than 10 test_proxy tasks running simultaneously
        semaphore = asyncio.Semaphore(10) # Controls the number of nodes tested concurrently

        tasks = []
        for proxy in valid_proxies:
            async def limited_test():
                async with semaphore:
                    return await test_proxy(proxy, session, './tools/clash')
            tasks.append(limited_test())
        
        # Collect all results
        all_results = []
        # Use tqdm or other methods to display progress (optional, but limited effect in GH Actions logs)
        for i, future in enumerate(asyncio.as_completed(tasks)):
            result = await future
            if isinstance(result, dict):
                all_results.append(result)
                with open('data/521.yaml', 'a') as f:
                    yaml.dump([result], f, allow_unicode=True, indent=2) # Increase indent for readability
                print(f"{result['name']}: {result['status']}{'，Latency: %.2fms' % result['latency'] if result['latency'] else ''}{'，Error: ' + result['error'] if result['error'] else ''}")
            else:
                # Handle exceptions, e.g., asyncio.CancelledError
                print(f"Task completed with an exception: {result}")

if __name__ == "__main__":
    asyncio.run(main())
