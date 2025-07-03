import requests
import os
import re
import datetime
import urllib.parse
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def standardize_node_minimal(node_url):
    """
    标准化明文节点URL，只保留其核心连接信息，去除所有非必要参数和备注，
    以实现最小化去重和文件体积。
    支持 hysteria2, vmess, trojan, ss, ssr, vless 等明文协议链接。
    """
    if not node_url:
        return None

    # 清除URL末尾可能存在的空白字符、回车或多余的斜杠
    node_url = node_url.strip().rstrip('/')

    # 识别协议 (忽略大小写)
    match = re.match(r"^(?P<protocol>hysteria2|vmess|trojan|ss|ssr|vless)://(?P<data>.*)", node_url, re.IGNORECASE)
    if not match:
        logging.debug(f"不支持的协议或格式错误: {node_url}")
        return None

    protocol = match.group("protocol").lower() # 协议统一小写
    data_part = match.group("data") # 协议头之后的部分
    
    # 构建最终的精简节点字符串，也是去重键
    minimal_node_parts = [protocol + "://"]

    try:
        # 去除URL末尾的 #name 标记及所有查询参数，只保留核心连接部分
        core_data = data_part.split('?', 1)[0].split('#', 1)[0].strip()
        core_data_standardized = urllib.parse.unquote_plus(core_data).strip()

        if protocol == "vmess" or protocol == "vless":
            # 对于vmess/vless，核心是 uuid@host:port
            # 无论原始链接是否带uuid，都尝试解析出 host:port 和 uuid
            parts = core_data_standardized.split('@', 1)
            if len(parts) == 2:
                # UUID 小写，地址端口小写
                minimal_node_parts.append(f"{parts[0].lower()}@{parts[1].lower()}")
            else: # 如果没有uuid，可能是直接的host:port
                minimal_node_parts.append(core_data_standardized.lower())

        elif protocol == "trojan" or protocol == "hysteria2":
            # 对于trojan/hysteria2，核心是 password@host:port
            parts = core_data_standardized.split('@', 1)
            if len(parts) == 2:
                # 密码保持原样，地址端口小写
                minimal_node_parts.append(f"{parts[0]}@{parts[1].lower()}")
            else:
                minimal_node_parts.append(core_data_standardized)

        elif protocol == "ss":
            # ss明文核心是 method:password@host:port
            if '@' in core_data_standardized and ':' in core_data_standardized.split('@')[0]:
                try:
                    auth_info, server_info = core_data_standardized.split('@', 1)
                    method = auth_info.split(':', 1)[0].lower() # 方法小写
                    password = auth_info.split(':', 1)[1] # 密码保持原样
                    host, port = server_info.split(':', 1)
                    
                    minimal_node_parts.append(f"{method}:{password}@{host.lower()}:{port.lower()}")
                except ValueError:
                    logging.debug(f"无法解析SS明文核心格式: {node_url}")
                    return None
            else:
                logging.debug(f"SS协议无法识别或核心解析失败: {node_url}")
                return None

        elif protocol == "ssr":
            # ssr明文核心是 host:port:protocol:method:obfs:password
            parts = core_data_standardized.split(':')
            if len(parts) >= 6: # 确保有足够的部分
                host = parts[0].lower()
                port = parts[1].lower()
                proto = parts[2].lower()
                method = parts[3].lower()
                obfs = parts[4].lower()
                password = parts[5] # 密码保持原样

                minimal_node_parts.append(f"{host}:{port}:{proto}:{method}:{obfs}:{password}")
            else:
                logging.debug(f"无法解析SSR明文核心格式: {node_url}")
                return None
        
        # 将所有精简部分连接起来
        return "".join(minimal_node_parts)

    except Exception as e:
        logging.error(f"标准化明文节点 {node_url} 时发生错误: {e}", exc_info=True)
        return None

def download_and_deduplicate_nodes():
    """
    从一系列GitHub Raw链接下载明文节点数据，只保留核心信息并去重后保存到文件。
    """
    base_url = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes_part_"
    start_index = 1
    end_index = 199 
    
    # unique_nodes 字典现在存储的是：
    # key: 精简后的节点字符串 (用于去重)
    # value: 精简后的节点字符串 (也是最终保存到文件的内容)
    unique_nodes = set() # 直接用set存储精简后的唯一节点字符串，更高效
    download_count = 0
    total_nodes_processed = 0
    failed_to_standardize_count = 0
    
    logging.info("--- 开始下载和去重精简节点 ---")
    start_time = datetime.datetime.now()

    for i in range(start_index, end_index + 1):
        file_index = str(i).zfill(3)
        url = f"{base_url}{file_index}.txt"
        
        try:
            logging.info(f"正在下载: {url}")
            response = requests.get(url, timeout=20) 
            response.raise_for_status()  
            download_count += 1
            
            nodes = response.text.strip().split('\n')
            for node in nodes:
                node = node.strip()
                if not node:
                    continue
                
                total_nodes_processed += 1
                # 调用精简标准化函数
                minimal_node = standardize_node_minimal(node)
                
                if minimal_node:
                    unique_nodes.add(minimal_node) # 直接添加到set中去重
                else:
                    failed_to_standardize_count += 1
                    logging.warning(f"无法标准化明文节点 (跳过): {node}") 

        except requests.exceptions.RequestException as e:
            logging.error(f"下载失败 {url}: {e}")
        except Exception as e:
            logging.error(f"处理 {url} 时发生未知错误: {e}", exc_info=True)

    os.makedirs('data', exist_ok=True)
    output_file = os.path.join('data', 'all.txt')

    # 将去重后的精简节点字符串排序后写入文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for node in sorted(list(unique_nodes)): 
            f.write(node + '\n')
    
    end_time = datetime.datetime.now()
    duration = end_time - start_time

    logging.info("\n--- 运行摘要 ---")
    logging.info(f"总共下载的链接数: {download_count}")
    logging.info(f"处理的节点总数 (包含重复和无效): {total_nodes_processed}")
    logging.info(f"无法标准化的节点数 (可能格式不符): {failed_to_standardize_count}")
    logging.info(f"精简并去重后的有效节点总数: {len(unique_nodes)}")
    logging.info(f"节点已保存到: {output_file}")
    logging.info(f"总耗时: {duration.total_seconds():.2f} 秒")
    logging.info("------------------")

if __name__ == "__main__":
    download_and_deduplicate_nodes()
