const axios = require('axios');
const fs = require('fs').promises;
const url = require('url');

async function fetchNodes() {
  try {
    const response = await axios.get('https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt');
    return response.data.split('\n').filter(line => line.trim());
  } catch (error) {
    console.error('Error fetching nodes:', error.message);
    return [];
  }
}

function parseNode(line) {
  const protocols = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless'];
  const protocolRegex = new RegExp(`^(${protocols.join('|')}):\/\/`, 'i');
  const match = line.match(protocolRegex);
  if (!match) return null;

  const protocol = match[1].toLowerCase();
  let host = '', port = '';

  try {
    if (protocol === 'vmess') {
      const decoded = Buffer.from(line.replace('vmess://', ''), 'base64').toString();
      const config = JSON.parse(decoded);
      host = config.add;
      port = config.port;
    } else if (protocol === 'trojan' || protocol === 'vless') {
      const parsed = url.parse(line);
      host = parsed.hostname;
      port = parsed.port;
    } else if (protocol === 'hysteria2') {
      const parsed = url.parse(line);
      host = parsed.hostname;
      port = parsed.port || 443;
    } else if (protocol === 'ss' || protocol === 'ssr') {
      const decoded = Buffer.from(line.replace(`${protocol}://`, ''), 'base64').toString();
      const parts = decoded.split(/[@:]/);
      host = parts[parts.length - 2];
      port = parts[parts.length - 1].split('#')[0];
    }
    return { protocol, host, port, raw: line };
  } catch (error) {
    console.error(`Error parsing ${protocol} node:`, error.message);
    return null;
  }
}

async function testNode(node) {
  if (!node) return false;
  try {
    // 使用 HTTP GET 测试连通性（简单示例，实际可能需要协议特定测试）
    const response = await axios.get(`http://${node.host}:${node.port}`, { timeout: 5000 });
    return response.status === 200;
  } catch (error) {
    try {
      // 备用测试：ping host
      const pingResponse = await axios.get(`http://${node.host}`, { timeout: 5000 });
      return pingResponse.status === 200;
    } catch (pingError) {
      console.error(`Failed to connect to ${node.host}:${node.port}:`, pingError.message);
      return false;
    }
  }
}

async function main() {
  const nodes = await fetchNodes();
  const parsedNodes = nodes.map(parseNode).filter(node => node);
  
  // 去重基于 host 和 port
  const uniqueNodes = [];
  const seen = new Set();
  for (const node of parsedNodes) {
    const key = `${node.host}:${node.port}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueNodes.push(node);
    }
  }

  // 测试连通性
  const validNodes = [];
  for (const node of uniqueNodes) {
    const isValid = await testNode(node);
    if (isValid) {
      validNodes.push(node.raw);
      console.log(`Valid node: ${node.protocol}://${node.host}:${node.port}`);
    }
  }

  // 保存到 data/sub.txt
  try {
    await fs.mkdir('data', { recursive: true });
    await fs.writeFile('data/sub.txt', validNodes.join('\n'));
    console.log('Saved valid nodes to data/sub.txt');
  } catch (error) {
    console.error('Error saving nodes:', error.message);
  }
}

main();
