import yaml
import requests
import socket
import json
import os
import sys

# 缓存文件路径
CACHE_FILE = 'ip_cache.json'

def load_cache():
    """从文件中加载缓存数据。"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"警告: 无法加载缓存文件，将创建新的缓存。错误: {e}")
    return {}

def save_cache(cache):
    """将缓存数据保存到文件。"""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)

def resolve_domains(hosts, cache):
    """
    解析域名为IP地址，并从缓存中获取已有的IP。
    """
    ips_to_query = []
    host_to_ip_map = {}
    
    for host in hosts:
        if not host:
            continue
        
        # 尝试从缓存中获取IP地址
        cached_ip = cache.get(host)
        if cached_ip:
            host_to_ip_map[host] = cached_ip
            # 如果IP地址本身也在缓存中，则跳过
            if cached_ip in cache:
                continue

        try:
            ip_address = socket.gethostbyname(host)
            host_to_ip_map[host] = ip_address
            # 将新的解析结果添加到缓存中
            if host not in cache:
                cache[host] = ip_address
            
            # 如果IP地址不在缓存中，则加入待查询列表
            if ip_address not in cache:
                ips_to_query.append(ip_address)
        except socket.gaierror:
            print(f"警告: 无法解析域名: {host}", file=sys.stderr)
    return host_to_ip_map, ips_to_query

def get_country_codes_batch(ips, cache):
    """
    使用ip-api.com的批量接口查询IP地址的国家代码。
    """
    if not ips:
        return {}

    print(f"正在使用批量查询接口查询 {len(ips)} 个IP...")
    
    # 将IP列表分割成每批最多100个
    chunk_size = 100
    results = {}
    
    for i in range(0, len(ips), chunk_size):
        ip_chunk = ips[i:i + chunk_size]
        try:
            response = requests.post('http://ip-api.com/batch', json=ip_chunk, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for item in data:
                query_ip = item.get('query')
                if item['status'] == 'success' and query_ip:
                    country_code = item['countryCode']
                    results[query_ip] = country_code
                    print(f"  - IP {query_ip} 的国家代码是: {country_code}")
                elif query_ip:
                    print(f"  - IP {query_ip} 查询失败: {item.get('message', '未知错误')}")

        except Exception as e:
            print(f"批量查询失败: {e}", file=sys.stderr)
            return {}
            
    return results

def main():
    """
    主函数，用于下载、筛选和保存Clash配置。
    """
    cache = load_cache()
    
    include_codes = {'JP', 'KR', 'HK', 'TW', 'SG', 'MY', 'PH', 'VN', 'TH', 'LA', 'MM', 'RU', 'MN'}
    config_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash_config.yaml'
    
    print("开始下载配置文件...")
    try:
        response = requests.get(config_url)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
        print("配置文件下载并解析成功。")
    except Exception as e:
        print(f"下载或解析配置文件失败: {e}", file=sys.stderr)
        return
    
    if 'proxies' not in config:
        print('配置中没有找到 proxies 列表。', file=sys.stderr)
        return

    hosts = [proxy.get('server') for proxy in config['proxies'] if proxy.get('server')]
    print(f"配置文件中共有 {len(hosts)} 个代理服务器。")

    host_to_ip_map, ips_to_query = resolve_domains(hosts, cache)
    
    ip_to_country_map = get_country_codes_batch(ips_to_query, cache)
    
    # 更新缓存
    for ip, country_code in ip_to_country_map.items():
        cache[ip] = country_code
    
    # 筛选节点
    filtered_proxies = []
    total_proxies_checked = 0
    total_proxies_filtered = 0
    
    print("\n--- 筛选过程日志 ---")
    for proxy in config['proxies']:
        total_proxies_checked += 1
        host = proxy.get('server')
        if not host:
            print(f"警告: 节点 {proxy.get('name', '未知节点')} 没有服务器地址，已跳过。")
            continue
        
        ip_address = host_to_ip_map.get(host)
        if not ip_address:
            print(f"节点 {proxy.get('name', host)} 的IP地址未知，已过滤。")
            total_proxies_filtered += 1
            continue
            
        country_code = cache.get(ip_address)
        if country_code and country_code in include_codes:
            filtered_proxies.append(proxy)
            print(f"✅ 节点 {proxy.get('name', host)} (IP: {ip_address}) 匹配国家代码 {country_code}，已保留。")
        else:
            print(f"❌ 节点 {proxy.get('name', host)} (IP: {ip_address}) 不匹配国家代码 {country_code if country_code else '未知'}，已过滤。")
            total_proxies_filtered += 1

    config['proxies'] = filtered_proxies
    
    with open('filtered_by_ip.yaml', 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    
    print("\n--- 筛选结果总结 ---")
    print(f"总共检查了 {total_proxies_checked} 个节点。")
    print(f"已成功筛选出 {len(filtered_proxies)} 个节点，并保存到 filtered_by_ip.yaml。")
    print(f"被过滤的节点数: {total_proxies_filtered}")
    
    # 保存更新后的缓存
    save_cache(cache)

if __name__ == '__main__':
    main()
