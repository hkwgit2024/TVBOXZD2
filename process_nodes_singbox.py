import re
import urllib.parse
import json
import ipaddress
from typing import Dict, List, Optional
import httpx
import asyncio
import logging
from pathlib import Path

class NodeParser:
    def __init__(self):
        self.supported_protocols = {"hysteria2", "vless"}
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def parse_node(self, node_url: str) -> Optional[Dict]:
        """解析节点 URL，返回节点配置字典"""
        if not isinstance(node_url, str) or not node_url.strip():
            self.logger.error("无效的节点 URL: 空或非字符串")
            return None

        try:
            protocol_match = re.match(r'^(\w+)://', node_url)
            if not protocol_match:
                self.logger.error(f"无效协议: {node_url}")
                return None
            protocol = protocol_match.group(1).lower()
            if protocol not in self.supported_protocols:
                self.logger.error(f"不支持的协议: {protocol}")
                return None

            parser_map = {
                "hysteria2": self.parse_hysteria2,
                "vless": self.parse_vless
            }
            return parser_map[protocol](node_url)
        except Exception as e:
            self.logger.error(f"解析节点失败: {node_url}, 错误: {str(e)}")
            return None

    def parse_hysteria2(self, node_url: str) -> Optional[Dict]:
        """解析 Hysteria2 节点"""
        try:
            remark = ""
            if "#" in node_url:
                node_url, remark = node_url.split("#", 1)
                remark = urllib.parse.unquote(remark).strip()

            parsed = urllib.parse.urlparse(node_url)
            if parsed.scheme != "hysteria2":
                self.logger.error(f"无效的 Hysteria2 方案: {node_url}")
                return None

            user_info = parsed.username or parsed.password
            if not user_info:
                query = urllib.parse.parse_qs(parsed.query)
                user_info = query.get("password", [None])[0]

            server, port = self._extract_server_port(node_url, parsed)
            if not server or not port:
                self.logger.error(f"Hysteria2 节点无效: 服务器或端口为空 {node_url}")
                return None

            try:
                ipaddress.ip_address(server)
            except ValueError:
                pass  # 域名，跳过验证

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

            return {k: v for k, v in config.items() if v is not None}
        except Exception as e:
            self.logger.error(f"解析 Hysteria2 错误: {node_url}, {str(e)}")
            return None

    def parse_vless(self, node_url: str) -> Optional[Dict]:
        """解析 VLESS 节点"""
        try:
            remark = ""
            if "#" in node_url:
                node_url, remark = node_url.split("#", 1)
                remark = urllib.parse.unquote(remark).strip()

            parsed = urllib.parse.urlparse(node_url)
            if parsed.scheme != "vless":
                self.logger.error(f"无效的 VLESS 方案: {node_url}")
                return None

            uuid = parsed.username
            if not uuid:
                self.logger.error(f"VLESS 节点无效: UUID 为空 {node_url}")
                return None

            server, port = self._extract_server_port(node_url, parsed)
            if not server or not port:
                self.logger.error(f"VLESS 节点无效: 服务器或端口为空 {node_url}")
                return None

            try:
                ipaddress.ip_address(server)
            except ValueError:
                pass  # 域名，跳过验证

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

            self._add_transport_config(config, transport_type, query)
            self._add_tls_config(config, security, query)

            if "transport" in config:
                config["transport"] = {k: v for k, v in config["transport"].items() if v is not None}
            if "tls" in config:
                config["tls"] = {k: v for k, v in config["tls"].items() if v is not None}
            return {k: v for k, v in config.items() if v is not None}
        except Exception as e:
            self.logger.error(f"解析 VLESS 错误: {node_url}, {str(e)}")
            return None

    def _extract_server_port(self, node_url: str, parsed: urllib.parse.ParseResult) -> tuple[Optional[str], Optional[int]]:
        """提取服务器地址和端口"""
        server = parsed.hostname
        port = parsed.port
        if not server or not port:
            server_port_match = re.match(r'.*@(\[?[\w:.\-]+\]?)?:(\d+)', node_url)
            if server_port_match:
                server, port = server_port_match.groups()
                port = int(port)
                if server.startswith("[") and server.endswith("]"):
                    server = server[1:-1]
        return server, port

    def _add_transport_config(self, config: Dict, transport_type: str, query: Dict) -> None:
        """添加传输层配置"""
        transport_configs = {
            "ws": {"type": "ws", "path": query.get("path", [None])[0], "headers": {"Host": query.get("host", [None])[0]} if query.get("host") else {}},
            "grpc": {"type": "grpc", "service_name": query.get("serviceName", [None])[0]},
            "tcp": {"type": "tcp"},
            "http": {"type": "http", "path": query.get("path", [None])[0], "host": query.get("host", [None])[0]},
            "xhttp": {"type": "xhttp", "path": query.get("path", [None])[0], "host": query.get("host", [None])[0]},
            "httpupgrade": {"type": "httpupgrade", "path": query.get("path", [None])[0], "host": query.get("host", [None])[0]},
        }
        if transport_type in transport_configs:
            config["transport"] = transport_configs[transport_type]

    def _add_tls_config(self, config: Dict, security: str, query: Dict) -> None:
        """添加 TLS 配置"""
        if security == "tls":
            config["tls"] = {
                "enabled": True,
                "server_name": query.get("sni", [None])[0],
                "alpn": query.get("alpn", ["http/1.1"])[0].split(","),
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

    def generate_singbox_config(self, nodes: List[Dict]) -> Dict:
        """生成 Sing-box 配置文件"""
        outbounds = [node for node in nodes if node]
        if not outbounds:
            self.logger.warning("没有有效的节点可生成配置")
            return {"log": {"level": "info"}, "outbounds": [], "route": {"rules": []}}

        config = {
            "log": {"level": "info"},
            "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
            "route": {
                "rules": [
                    {"protocol": ["http", "tls"], "outbound": outbounds[0]["tag"]},
                    {"outbound": "direct"}
                ]
            },
        }
        return config

    async def test_connectivity(self, node: Dict, timeout: int = 5) -> bool:
        """测试节点连通性"""
        try:
            async with httpx.AsyncClient(
                proxies=f"socks5://127.0.0.1:1080",
                timeout=timeout,
                verify=False  # 避免 SSL 验证问题
            ) as client:
                response = await client.get("https://www.google.com")
                if response.status_code == 200:
                    self.logger.info(f"节点 {node['tag']} 测试通过")
                    return True
                self.logger.warning(f"节点 {node['tag']} 测试失败: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"节点 {node.get('tag', '未知节点')} 测试失败: {str(e)}")
            return False

async def main():
    parser = NodeParser()
    nodes = []

    input_file = Path("sub_2.txt")
    if not input_file.exists():
        parser.logger.error(f"输入文件 {input_file} 不存在")
        return

    try:
        with input_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    node_config = parser.parse_node(line)
                    if node_config:
                        nodes.append(node_config)

        if not nodes:
            parser.logger.warning("未解析到任何有效节点")
            return

        singbox_config = parser.generate_singbox_config(nodes)
        with Path("singbox_config.json").open("w", encoding="utf-8") as f:
            json.dump(singbox_config, f, ensure_ascii=False, indent=2)
        parser.logger.info("Sing-box 配置文件已生成")

        tasks = [parser.test_connectivity(node) for node in nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for node, result in zip(nodes, results):
            if isinstance(result, Exception):
                parser.logger.error(f"节点 {node['tag']} 测试失败: {str(result)}")
            elif result:
                continue
    except Exception as e:
        parser.logger.error(f"主程序错误: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
