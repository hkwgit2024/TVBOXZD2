import re
import urllib.parse
import json
import ipaddress
from typing import Dict, Optional
import httpx
import asyncio

class NodeParser:
    def __init__(self):
        self.supported_protocols = ["hysteria2", "vless"]

    def parse_node(self, node_url: str) -> Optional[Dict]:
        """解析节点 URL，返回节点配置字典"""
        try:
            # 提取协议
            protocol_match = re.match(r'^(\w+)://', node_url)
            if not protocol_match:
                print(f"无效协议: {node_url}")
                return None
            protocol = protocol_match.group(1).lower()
            if protocol not in self.supported_protocols:
                print(f"不支持的协议: {protocol}")
                return None

            if protocol == "hysteria2":
                return self.parse_hysteria2(node_url)
            elif protocol == "vless":
                return self.parse_vless(node_url)
        except Exception as e:
            print(f"解析节点失败: {node_url}, 错误: {str(e)}")
            return None

    def parse_hysteria2(self, node_url: str) -> Optional[Dict]:
        """解析 Hysteria2 节点"""
        try:
            # 分离 URL 和备注
            remark = ""
            if "#" in node_url:
                node_url, remark = node_url.split("#", 1)
                remark = urllib.parse.unquote(remark)

            # 解析 URL
            parsed = urllib.parse.urlparse(node_url)
            if not parsed.scheme == "hysteria2":
                return None

            # 提取用户和服务器信息
            user_info = parsed.username or parsed.password
            if not user_info:
                # 检查是否通过 ?password= 指定
                query = urllib.parse.parse_qs(parsed.query)
                user_info = query.get("password", [None])[0]

            # 提取服务器地址和端口
            server = parsed.hostname
            port = parsed.port
            if not server or not port:
                # 尝试正则匹配 IPv6 或非标准格式
                server_port_match = re.match(r'.*@(\[?[\w:.\-]+\]?)?:(\d+)', node_url)
                if server_port_match:
                    server, port = server_port_match.groups()
                    port = int(port)
                    if server.startswith("[") and server.endswith("]"):
                        server = server[1:-1]

            if not server or not port:
                print(f"Hysteria2 节点无效: 服务器或端口为空 {node_url}")
                return None

            # 验证服务器地址
            try:
                ipaddress.ip_address(server)
            except ValueError:
                # 可能是域名，保留原样
                pass

            # 提取查询参数
            query = urllib.parse.parse_qs(parsed.query)
            config = {
                "type": "hysteria2",
                "tag": remark or f"hysteria2-{server}:{port}",
                "server": server,
                "server_port": port,
                "password": user_info,
                "sni": query.get("sni", [None])[0],
                "insecure": query.get("insecure", ["0"])[0] == "1",
                "obfs": query.get("obfs", [None])[0],
                "obfs-password": query.get("obfs-password", [None])[0] or query.get("obfsParam", [None])[0],
                "up_mbps": int(query.get("up_mbps", [0])[0]) if query.get("up_mbps") else None,
                "down_mbps": int(query.get("down_mbps", [0])[0]) if query.get("down_mbps") else None,
            }

            # 清理空值
            config = {k: v for k, v in config.items() if v is not None}
            return config
        except Exception as e:
            print(f"解析 Hysteria2 错误: {node_url}, {str(e)}")
            return None

    def parse_vless(self, node_url: str) -> Optional[Dict]:
        """解析 VLESS 节点"""
        try:
            # 分离 URL 和备注
            remark = ""
            if "#" in node_url:
                node_url, remark = node_url.split("#", 1)
                remark = urllib.parse.unquote(remark)

            # 解析 URL
            parsed = urllib.parse.urlparse(node_url)
            if not parsed.scheme == "vless":
                return None

            # 提取 UUID
            uuid = parsed.username
            if not uuid:
                print(f"VLESS 节点无效: UUID 为空 {node_url}")
                return None

            # 提取服务器地址和端口
            server = parsed.hostname
            port = parsed.port
            if not server or not port:
                # 尝试正则匹配
                server_port_match = re.match(r'.*@(\[?[\w:.\-]+\]?)?:(\d+)', node_url)
                if server_port_match:
                    server, port = server_port_match.groups()
                    port = int(port)
                    if server.startswith("[") and server.endswith("]"):
                        server = server[1:-1]

            if not server or not port:
                print(f"VLESS 节点无效: 服务器或端口为空 {node_url}")
                return None

            # 验证服务器地址
            try:
                ipaddress.ip_address(server)
            except ValueError:
                # 可能是域名，保留原样
                pass

            # 提取查询参数
            query = urllib.parse.parse_qs(parsed.query)
            transport_type = query.get("type", ["tcp"])[0].lower()
            security = query.get("security", ["none"])[0].lower()

            config = {
                "type": "vless",
                "tag": remark or f"vless-{server}:{port}",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": security,
                "encryption": query.get("encryption", ["none"])[0],
            }

            # 处理传输层
            if transport_type == "ws":
                config["transport"] = {
                    "type": "ws",
                    "path": query.get("path", [None])[0],
                    "headers": {"Host": query.get("host", [None])[0]} if query.get("host") else {},
                }
            elif transport_type == "grpc":
                config["transport"] = {
                    "type": "grpc",
                    "service_name": query.get("serviceName", [None])[0],
                }
            elif transport_type in ["tcp", "http", "xhttp", "httpupgrade"]:
                config["transport"] = {"type": transport_type}
                if transport_type in ["http", "xhttp", "httpupgrade"]:
                    config["transport"]["path"] = query.get("path", [None])[0]
                    config["transport"]["host"] = query.get("host", [None])[0]

            # 处理 TLS 和 Reality
            if security == "tls":
                config["tls"] = {
                    "enabled": True,
                    "server_name": query.get("sni", [None])[0],
                    "alpn": query.get("alpn", ["http/1.1"]).split(","),
                    "utls": query.get("fp", ["chrome"])[0],
                }
            elif security == "reality":
                config["tls"] = {
                    "enabled": True,
                    "server_name": query.get("sni", [None])[0],
                    "reality": {
                        "enabled": True,
                        "public_key": query.get("pbk", [None])[0],
                        "short_id": query.get("sid", [None])[0],
                    },
                }

            # 清理空值
            config = {k: v for k, v in config.items() if v is not None}
            if "transport" in config:
                config["transport"] = {k: v for k, v in config["transport"].items() if v is not None}
            if "tls" in config:
                config["tls"] = {k: v for k, v in config["tls"].items() if v is not None}
            return config
        except Exception as e:
            print(f"解析 VLESS 错误: {node_url}, {str(e)}")
            return None

    def generate_singbox_config(self, nodes: list) -> Dict:
        """生成 Sing-box 配置文件"""
        outbounds = []
        for node in nodes:
            if not node:
                continue
            outbounds.append(node)

        config = {
            "log": {"level": "info"},
            "outbounds": outbounds,
            "route": {
                "rules": [
                    {"protocol": ["http", "tls"], "outbound": outbounds[0]["tag"] if outbounds else "direct"},
                ]
            },
        }
        return config

    async def test_connectivity(self, node: Dict, timeout: int = 5) -> bool:
        """测试节点连通性"""
        try:
            async with httpx.AsyncClient(
                proxies=f"socks5://127.0.0.1:1080", timeout=timeout
            ) as client:
                response = await client.get("https://www.google.com")
                return response.status_code == 200
        except Exception as e:
            print(f"连通性测试失败: {node.get('tag', '未知节点')}, 错误: {str(e)}")
            return False

async def main():
    parser = NodeParser()
    nodes = []

    # 读取节点文件
    with open("sub_2.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                node_config = parser.parse_node(line)
                if node_config:
                    nodes.append(node_config)

    # 生成 Sing-box 配置
    singbox_config = parser.generate_singbox_config(nodes)
    with open("singbox_config.json", "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, ensure_ascii=False, indent=2)

    # 测试连通性（需运行 Sing-box）
    for node in nodes:
        if await parser.test_connectivity(node):
            print(f"节点 {node['tag']} 测试通过")
        else:
            print(f"节点 {node['tag']} 测试失败")

if __name__ == "__main__":
    asyncio.run(main())
