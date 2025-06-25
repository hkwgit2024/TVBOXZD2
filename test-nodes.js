const axios = require('axios');
const fs = require('fs').promises;
const url = require('url');
let PQueue;

try {
  PQueue = require('p-queue').default || require('p-queue'); // Handle different export styles
  console.log('p-queue loaded successfully, version:', require('p-queue/package.json').version);
} catch (error) {
  console.warn('Failed to load p-queue, falling back to sequential processing:', error.message);
  PQueue = null;
}

const queue = PQueue ? new PQueue({ concurrency: 10 }) : { add: async (fn) => await fn() }; // Fallback to sequential
const SOURCE_URL = 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt';
const OUTPUT_PATH = 'data/sub.txt';
const MAX_RETRIES = 2;
const TIMEOUT = 5000;

async function fetchNodes() {
  try {
    const response = await axios.get(SOURCE_URL, { timeout: TIMEOUT });
    const nodes = response.data.split('\n').filter(line => line.trim());
    if (nodes.length === 0) throw new Error('No nodes found in source file');
    console.log(`Fetched ${nodes.length} nodes`);
    return nodes;
  } catch (error) {
    console.error('Error fetching nodes:', error.message);
    return [];
  }
}

function parseNode(line) {
  const protocols = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless'];
  const protocolRegex = new RegExp(`^(${protocols.join('|')}):\/\/`, 'i');
  const match = line.match(protocolRegex);
  if (!match) {
    console.warn(`Invalid node format: ${line.slice(0, 50)}...`);
    return null;
  }

  const protocol = match[1].toLowerCase();
  let host = '', port = '', uniqueId = '';

  try {
    if (protocol === 'vmess') {
      const decoded = Buffer.from(line.replace('vmess://', ''), 'base64').toString();
      const config = JSON.parse(decoded);
      host = config.add;
      port = config.port;
      uniqueId = config.id; // 使用 UUID 作为去重标识
    } else if (protocol === 'trojan' || protocol === 'vless') {
      const parsed = url.parse(line);
      host = parsed.hostname;
      port = parsed.port;
      uniqueId = parsed.auth || host; // trojan 使用密码，vless 使用 UUID
    } else if (protocol === 'hysteria2') {
      const parsed = url.parse(line);
      host = parsed.hostname;
      port = parsed.port || 443;
      uniqueId = parsed.auth || host;
    } else if (protocol === 'ss' || protocol === 'ssr') {
      const decoded = Buffer.from(line.replace(`${protocol}://`, ''), 'base64').toString();
      const parts = decoded.split(/[@:]/);
      host = parts[parts.length - 2];
      port = parts[parts.length - 1].split('#')[0];
      uniqueId = parts[0]; // 使用加密方法或密码作为去重标识
    }
    return { protocol, host, port, uniqueId, raw: line };
  } catch (error) {
    console.error(`Error parsing ${protocol} node: ${line.slice(0, 50)}...`, error.message);
    return null;
  }
}

async function testNode(node) {
  if (!node) return false;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      // 尝试 HTTP GET 测试
      const response = await axios.get(`http://${node.host}:${node.port}`, { timeout: TIMEOUT });
      if (response.status === 200) {
        console.log(`Valid node: ${node.protocol}://${node.host}:${node.port} (Attempt ${attempt})`);
        return true;
      }
    } catch (error) {
      try {
        // 备用 ping 测试
        const pingResponse = await axios.get(`http://${node.host}`, { timeout: TIMEOUT });
        if (pingResponse.status === 200) {
          console.log(`Valid node (ping): ${node.protocol}://${node.host}:${node.port} (Attempt ${attempt})`);
          return true;
        }
      } catch (pingError) {
        console.warn(`Attempt ${attempt} failed for ${node.host}:${node.port}: ${pingError.message}`);
      }
    }
  }
  console.error(`Node failed after ${MAX_RETRIES} attempts: ${node.protocol}://${node.host}:${node.port}`);
  return false;
}

async function main() {
  console.log(`Running with Node.js ${process.version} at ${new Date().toISOString()}`);
  const nodes = await fetchNodes();
  if (nodes.length === 0) {
    console.error('No nodes to process, exiting');
    return;
  }

  const parsedNodes = nodes.map(parseNode).filter(node => node);
  console.log(`Parsed ${parsedNodes.length} valid nodes`);

  // 去重基于 host, port 和 uniqueId
  const uniqueNodes = [];
  const seen = new Set();
  for (const node of parsedNodes) {
    const key = `${node.protocol}:${node.host}:${node.port}:${node.uniqueId}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueNodes.push(node);
    }
  }
  console.log(`After deduplication: ${uniqueNodes.length} unique nodes`);

  // 并行测试连通性
  const testResults = await Promise.allSettled(uniqueNodes.map(node => queue.add(() => testNode(node))));
  const validNodes = uniqueNodes.filter((node, index) => testResults[index].status === 'fulfilled' && testResults[index].value);

  // 格式化输出
  const output = [
    `# Valid nodes (Tested on ${new Date().toISOString()})`,
    ...validNodes.map(node => `${node.raw} # ${node.protocol}`)
  ];

  // 保存到 data/sub.txt
  try {
    await fs.mkdir('data', { recursive: true });
    await fs.writeFile(OUTPUT_PATH, output.join('\n'));
    console.log(`Saved ${validNodes.length} valid nodes to ${OUTPUT_PATH}`);
  } catch (error) {
    console.error('Error saving nodes:', error.message);
  }
}

main().catch(error => {
  console.error('Main process error:', error.message);
  process.exit(1);
});
