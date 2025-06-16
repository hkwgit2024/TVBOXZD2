const fs = require('fs/promises'); // 用于异步文件操作
const yaml = require('js-yaml');    // 用于解析 YAML 文件
const path = require('path');       // 用于路径操作
const { PromisePool } = require('@supercharge/promise-pool'); // 用于控制并发
const { spawn } = require('child_process'); // 用于启动/停止Clash进程
const { setTimeout, clearTimeout } = require('timers'); // 用于异步延迟和清除延迟
const { ProxyAgent } = require('undici'); // 用于配置 fetch 使用代理

// --- 辅助函数 ---

/**
 * 测试延迟到给定 URL，通过配置的代理。
 * @param {string} url - 要测试的 URL。
 * @param {number} timeout - 超时时间（毫秒）。
 * @param {ProxyAgent} proxyAgent - 用于 fetch 请求的 Undici ProxyAgent 实例。
 * @returns {Promise<number|string>} 成功则返回延迟（毫秒），否则返回错误字符串。
 */
async function testLatency(url, timeout = 5000, proxyAgent) { // 增加默认超时时间到 5000ms
    const start = Date.now();
    let timeoutId; // 用于存储 setTimeout 返回的 ID
    try {
        const controller = new AbortController();
        // 使用全局的 setTimeout 来设置 AbortController 的超时，并获取其返回的 ID
        timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal,
            dispatcher: proxyAgent // 使用传入的代理 agent
        });
        clearTimeout(timeoutId); // 清除超时计时器

        if (response.ok) {
            return Date.now() - start; // 返回延迟毫秒数
        } else {
            return `HTTP Error: ${response.status} ${response.statusText}`;
        }
    } catch (error) {
        // 确保清除可能存在的 timeoutId，以防错误在 clearTimeout 之前发生
        if (timeoutId) {
            clearTimeout(timeoutId);
        }

        if (error.name === 'AbortError') {
            return `超时 (${timeout}ms)`;
        } else if (error.cause && error.cause.code) { // 捕获更具体的网络错误码 (ECONNRESET, ECONNREFUSED, UND_ERR_SOCKET)
            return `网络错误: ${error.cause.code}`;
        }
        return `连接错误: ${error.message.substring(0, 50)}...`; // 截断错误信息
    }
}

/**
 * 根据代理信息和指定的端口生成一个临时的 Clash 配置文件。
 * @param {object} proxy - 来自 520.yaml 的代理对象。
 * @param {number} port - Clash 客户端将监听的 HTTP 代理端口。
 * @returns {string} YAML 配置文件字符串。
 */
function generateClashConfig(proxy, port = 7890) {
    // 强制验证基本代理字段
    if (!proxy.server || !proxy.port || !proxy.type) {
        throw new Error('Invalid proxy config: missing server, port, or type');
    }

    const config = {
        port: port,
        'socks-port': port + 1, // SOCKS5 端口
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info', // 调试时建议 info，上线可改为 error 或 silent
        'external-controller': `127.0.0.1:${port + 2}`, // 面板端口
        proxies: [],
        'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: [] }],
        rules: ['MATCH,Proxy'] // 所有流量都走 Proxy 组
    };

    // 确保代理名称是有效的，替换掉特殊字符
    const proxyName = (proxy.name || `proxy-${Math.random().toString(36).substring(7)}`).replace(/[^a-zA-Z0-9_-]/g, '_');
    
    let clashProxy = {
        name: proxyName,
        type: proxy.type.toLowerCase(), // 统一使用小写
        server: proxy.server,
        port: proxy.port,
        udp: proxy.udp || false,
        'skip-cert-verify': proxy['skip-cert-verify'] || false // 默认不跳过证书验证，提高安全性
    };

    // 根据代理类型添加特定参数
    switch (proxy.type.toLowerCase()) {
        case 'vless':
            if (!proxy.uuid) throw new Error('VLESS requires uuid');
            clashProxy.uuid = proxy.uuid;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            // 处理 VLESS 的 network 类型和相关配置
            if (proxy.network) { clashProxy.network = proxy.network; }
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy['ws-opts'] = proxy['ws-opts']; // 复制整个 ws-opts 对象
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy['grpc-opts'] = proxy['grpc-opts']; // 复制整个 grpc-opts 对象
            }
            // 根据需要添加其他 network 类型的处理 (e.g., h2-opts, http-opts)
            break;
        case 'trojan':
            if (!proxy.password) throw new Error('Trojan requires password');
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            // 处理 Trojan 的 network 类型和相关配置
            if (proxy.network) { clashProxy.network = proxy.network; }
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy['ws-opts'] = proxy['ws-opts'];
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy['grpc-opts'] = proxy['grpc-opts'];
            }
            break;
        case 'ss': // Shadowsocks
            if (!proxy.cipher || !proxy.password) throw new Error('SS requires cipher and password');
            clashProxy.cipher = proxy.cipher;
            clashProxy.password = proxy.password;
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            if (proxy.obfsHost) clashProxy.obfsHost = proxy.obfsHost;
            if (proxy.plugin) clashProxy.plugin = proxy.plugin;
            if (proxy.pluginOpts) clashProxy.pluginOpts = proxy.pluginOpts;
            break;
        case 'ssr': // ShadowsocksR
            if (!proxy.password || !proxy.cipher) throw new Error('SSR requires password and cipher');
            clashProxy.password = proxy.password;
            clashProxy.cipher = proxy.cipher;
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            if (proxy.protocol) clashProxy.protocol = proxy.protocol;
            if (proxy.obfsparam) clashProxy.obfsParam = proxy.obfsparam;
            if (proxy.protoparam) clashProxy.protocolParam = proxy.protoparam;
            break;
        case 'vmess':
            if (!proxy.uuid) throw new Error('VMess requires uuid');
            clashProxy.uuid = proxy.uuid;
            clashProxy.alterId = proxy.alterId || 0;
            clashProxy.cipher = proxy.cipher || 'auto';
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.network) { clashProxy.network = proxy.network; } // network (tcp, ws, http, h2, grpc)
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy['ws-opts'] = proxy['ws-opts'];
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy['grpc-opts'] = proxy['grpc-opts'];
            }
            break;
        case 'hysteria':
        case 'hy': // Hysteria v1
            if (!proxy.auth) throw new Error('Hysteria requires auth');
            clashProxy.auth = proxy.auth;
            clashProxy.network = proxy.network || 'udp';
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            if (proxy.ports) clashProxy.ports = proxy.ports;
            if (proxy.up) clashProxy.up = proxy.up;
            if (proxy.down) clashProxy.down = proxy.down;
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            if (proxy.obfsParam) clashProxy.obfsParam = proxy.obfsParam;
            clashProxy.fastOpen = proxy.fastOpen || false;
            break;
        case 'hysteria2':
        case 'hy2': // Hysteria v2
            if (!proxy.password) throw new Error('Hysteria2 requires password');
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            clashProxy.fastOpen = proxy.fastOpen || false;
            // if (proxy['enable-multiplex']) { clashProxy['enable-multiplex'] = proxy['enable-multiplex']; }
            break;
        default:
            // 如果遇到不支持的类型，将抛出错误，而不是仅仅警告
            throw new Error(`Unsupported proxy type: ${proxy.type}`);
    }

    config.proxies.push(clashProxy);
    config['proxy-groups'][0].proxies.push(proxyName); // 将当前代理添加到默认的 'Proxy' 组

    return yaml.dump(config, { lineWidth: -1 });
}

/**
 * 检查 Clash 客户端的 API 是否已准备就绪。
 * @param {number} port - Clash 面板端口。
 * @param {number} retries - 重试次数。
 * @param {number} delay - 每次重试之间的延迟（毫秒）。
 * @returns {Promise<boolean>} 如果 Clash API 响应则返回 true，否则返回 false。
 */
async function checkClashReady(port, retries = 10, delay = 1000) { // 增加重试次数到 10，每次延迟 1 秒
    const controllerPort = port + 2; // 面板端口通常是 HTTP 代理端口 + 2
    for (let i = 0; i < retries; i++) {
        try {
            // 注意这里不使用 proxyAgent，直接连接到本地 Clash API
            const response = await fetch(`http://127.0.0.1:${controllerPort}/version`, { timeout: 2000 }); // 给 API 响应 2 秒超时
            if (response.ok) {
                console.log(`Clash API 在端口 ${controllerPort} 已准备就绪。`);
                return true;
            }
        } catch (error) {
            // 在重试期间，不打印警告以减少日志噪音，除非是最后一次重试
            if (i === retries - 1) {
                 console.warn(`Clash API 未就绪（端口 ${controllerPort}），最后一次尝试失败: ${error.message.substring(0,50)}`);
            }
        }
        await new Promise(resolve => setTimeout(resolve, delay)); // 使用全局 setTimeout
    }
    console.error(`Clash API 在端口 ${controllerPort} 启动失败或超时。`);
    return false;
}

/**
 * 尝试终止 Clash 进程并释放端口。
 * @param {number} pid - Clash 进程 ID。
 * @param {number} port - Clash HTTP 代理端口。
 */
async function killClashProcess(pid, port) {
    try {
        process.kill(pid, 'SIGTERM'); // 尝试发送 SIGTERM 信号
        await new Promise(resolve => setTimeout(resolve, 500)); // 等待进程优雅关闭
        console.log(`已尝试终止 Clash PID ${pid} (SIGTERM)。`);
    } catch (error) {
        if (error.code !== 'ESRCH') { // ESRCH 表示进程不存在，这是预期的
            console.warn(`WARNING: Failed to send SIGTERM to PID ${pid}: ${error.message}`);
        } else {
            console.log(`Clash PID ${pid} 已不存在（可能已退出）。`);
        }
    }

    // 强制终止残留进程并释放端口
    const { exec } = require('child_process');
    const portsToKill = [port, port + 1, port + 2];
    for (const p of portsToKill) {
        try {
            // 使用 lsof 和 kill -9 确保端口被强制释放
            // `-r` 选项用于 xargs: If the standard input consists solely of blank lines, or of zero-length non-blank lines if the -L or -t options are not used, no commands will be run.
            // `2>/dev/null` 再次确保 stderr 不会污染主输出，特别是当 `lsof` 没有找到进程时。
            await new Promise(resolve => exec(`lsof -ti :${p} | xargs -r kill -9 2>/dev/null`, (error, stdout, stderr) => {
                if (error) {
                    // 仅当错误信息不是因为“没有此类进程”或“命令未找到”时才警告
                    if (!stderr.includes('No such process') && !error.message.includes('No such process') && !error.message.includes('command not found')) {
                        console.warn(`WARN: 尝试强制终止端口 ${p} 失败: ${error.message.substring(0, 100)}...`);
                    }
                }
                resolve();
            }));
        } catch (e) {
            // 只有当 exec 本身同步抛出错误时（非常罕见）才会触发此处的 catch
            console.warn(`WARN: 强制终止端口 ${p} 时发生意外错误: ${e.message}`);
        }
    }
    console.log(`已尝试释放端口 ${port}, ${port+1}, ${port+2}。`);
}

// --- 主测试函数 ---
async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputConfigPath = path.join(__dirname, 'data', '521.yaml'); // 生成可导入的配置文件
    const outputReportPath = path.join(__dirname, 'data', '521_detailed_report.yaml'); // 生成详细的测试报告

    // 定义并发测试的 Clash 端口。每个并发实例使用一个独立的端口组。
    // 假设每个 Clash 实例需要 3 个端口 (HTTP, SOCKS, Controller)
    const basePorts = [7890, 7893, 7896, 7899, 7902]; // 5 个并发，每个端口组间隔 3

    // 默认测试目标 URL，用于判断代理是否连通
    const testUrl = 'http://www.gstatic.com/generate_204'; // 一个轻量级且稳定的 Google 无内容页面

    // 读取并解析输入文件
    let proxiesConfig;
    try {
        const fileContent = await fs.readFile(inputFilePath, 'utf8');
        proxiesConfig = yaml.load(fileContent);
        if (!proxiesConfig?.proxies?.length) {
            throw new Error('Invalid 520.yaml: no proxies found or file is empty.');
        }
    } catch (error) {
        console.error(`读取或解析 520.yaml 失败: ${error.message}`);
        return { timestamp: new Date().toISOString(), error: error.message };
    }

    // 预过滤无效代理：在测试前进行初步筛选，提高效率
    const invalidDomains = ['russia.com', 'singapore.com', 'japan.com', 'malaysia.com', 'example.com', 'www.hugedomains.com', 'ip.sb', 'xn--b6gac.eu.org', 'time.is', 'icook.hk', 'icook.tw', 'www.gov.ua']; // 增加更多已知无效或测试用的域名
    const validProxies = proxiesConfig.proxies.filter(proxy => {
        try {
            // 尝试生成配置，如果 generateClashConfig 抛出错误，则认为该代理无效
            generateClashConfig(proxy); // 只是尝试生成，不实际写入文件
            if (invalidDomains.includes(proxy.server)) {
                console.warn(`Skipping proxy ${proxy.name} (${proxy.server}): invalid/test server domain.`);
                return false;
            }
            return true;
        } catch (e) {
            console.warn(`Skipping proxy ${proxy.name} (type: ${proxy.type}): ${e.message}`);
            return false;
        }
    });

    console.log(`开始测试 ${validProxies.length} 个代理，最大并发数 ${basePorts.length} (通过 Clash 客户端)...`);

    const { results: testResults } = await PromisePool
        .for(validProxies)
        .withConcurrency(basePorts.length) // 使用 basePorts 的数量作为并发数
        .process(async (proxy, index) => {
            const port = basePorts[index % basePorts.length]; // 为每个任务分配一个基础端口
            const proxyAgent = new ProxyAgent(`http://127.0.0.1:${port}`); // 为当前 Clash 实例创建代理 agent
            
            const nodeName = proxy.name || 'Unknown';
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFileName = `clash-config-${safeNodeName}.yaml`;
            const configFilePath = path.join(__dirname, 'temp', configFileName);
            const clashExecutablePath = path.join(__dirname, 'tools', 'clash');

            let clashProcess = null;
            let latency = 'N/A';
            let status = 'Failed';
            let clashOutput = ''; // 用于捕获 Clash 进程的 stderr/stdout

            const result = {
                name: nodeName,
                server: proxy.server,
                port: proxy.port,
                type: proxy.type,
                test_target_url: testUrl,
                status: '未开始',
                latency_ms: 'N/A'
            };

            try {
                // 确保 temp 目录存在
                await fs.mkdir(path.join(__dirname, 'temp'), { recursive: true });

                // 1. 生成 Clash 配置
                const clashConfigContent = generateClashConfig(proxy, port); // 传入独立端口
                await fs.writeFile(configFilePath, clashConfigContent, 'utf8');
                // console.log(`  - 已生成 Clash 配置: ${configFileName}`); // 日志过多，调试时开启

                // 2. 启动 Clash 客户端
                clashProcess = spawn(clashExecutablePath, ['-f', configFilePath], {
                    detached: true, // 使子进程独立于父进程
                    stdio: ['ignore', 'pipe', 'pipe'] // 捕获 stdout/stderr 以便调试
                });

                // 捕获 Clash 进程的日志输出，以备调试
                clashProcess.stdout.on('data', data => clashOutput += data.toString());
                clashProcess.stderr.on('data', data => clashOutput += data.toString());

                clashProcess.unref(); // 允许 Node.js 进程在子进程结束后退出

                // 3. 等待 Clash 启动并初始化 (增加重试次数和延迟)
                if (!await checkClashReady(port, 10, 1000)) { // 尝试 10 次，每次等待 1 秒
                    throw new Error(`Clash failed to start or respond on port ${port}.`); // 移除日志中的 Clash output，因为它会在 finally 中统一打印
                }

                // 4. 执行实际的代理测试
                latency = await testLatency(testUrl, 5000, proxyAgent); // 增加测试超时到 5 秒
                status = typeof latency === 'number' ? '成功' : `失败: ${latency}`;
                result.latency_ms = latency;
                result.status = status;

            } catch (error) {
                status = `错误: ${error.message.substring(0, 100)}...`; // 捕获并截断错误信息
                console.warn(`测试失败 for ${nodeName}: ${status}`);
                result.status = status;
                result.latency_ms = 'N/A'; // 确保失败时延迟是 N/A
            } finally {
                // 5. 停止 Clash 客户端并清理临时文件
                if (clashProcess && !clashProcess.killed) {
                    await killClashProcess(clashProcess.pid, port);
                } else if (clashProcess && clashProcess.exitCode !== null) {
                    // 如果 Clash 进程已经退出（非手动终止），打印其退出码和捕获的日志
                    console.warn(`  - Clash 进程在测试前/中途异常退出 (${nodeName}). Exit Code: ${clashProcess.exitCode || 'N/A'}. Signal: ${clashProcess.signal || 'N/A'}`);
                }

                // 如果测试失败，且有 Clash 输出，打印 Clash 的日志
                if (result.status.startsWith('失败') || result.status.startsWith('错误')) {
                    if (clashOutput) {
                        console.error(`  - Clash 详细输出 (${nodeName}):\n${clashOutput.substring(0, 2000)}...\n`); // 打印 Clash 日志，截取前 2000 字符
                    } else {
                        console.warn(`  - Clash 未输出任何日志 (${nodeName})，可能启动失败或无详细错误信息。`);
                    }
                }

                try {
                    await fs.unlink(configFilePath); // 删除临时配置文件
                    // console.log(`  - 已删除临时配置文件: ${configFileName}`); // 日志过多，调试时开启
                } catch (unlinkError) {
                    // console.warn(`  - 无法删除临时配置文件 ${configFilePath}: ${unlinkError.message}`); // 调试时开启
                }
            }

            console.log(`测试完成 ${nodeName}: ${result.status}`); // 报告每个代理的最终状态
            return result;
        });

    // --- 后续处理：筛选成功的代理并生成输出文件 ---

    // 筛选出成功的代理结果
    const successfulProxies = testResults.filter(result => result.status === "成功");

    // 为可导入的 Clash 配置文件准备代理列表
    const importableProxies = successfulProxies.map(proxyResult => {
        // 根据测试结果的名字，从原始配置中找到完整的代理对象
        const originalProxy = proxiesConfig.proxies.find(p => {
            const originalNameSafe = (p.name || `proxy-${Math.random().toString(36).substring(7)}`).replace(/[^a-zA-Z0-9_-]/g, '_');
            const resultNameSafe = proxyResult.name.replace(/[^a-zA-Z0-9_-]/g, '_');
            return originalNameSafe === resultNameSafe;
        });

        // 重新调用 generateClashConfig 的部分逻辑来构建仅包含必要字段的代理对象
        // 这确保了最终配置的纯净性，且字段是 Clash 所需的
        if (originalProxy) {
             let cleanProxy = {
                name: originalProxy.name,
                type: originalProxy.type.toLowerCase(),
                server: originalProxy.server,
                port: originalProxy.port,
                udp: originalProxy.udp || false,
                'skip-cert-verify': originalProxy['skip-cert-verify'] || false
            };

            switch (originalProxy.type.toLowerCase()) {
                case 'vless':
                    cleanProxy.uuid = originalProxy.uuid;
                    cleanProxy.tls = originalProxy.tls || false;
                    if (originalProxy.servername) cleanProxy.servername = originalProxy.servername;
                    if (originalProxy.alpn) cleanProxy.alpn = originalProxy.alpn;
                    if (originalProxy.network) cleanProxy.network = originalProxy.network;
                    if (originalProxy.network === 'ws' && originalProxy['ws-opts']) {
                        cleanProxy['ws-opts'] = originalProxy['ws-opts'];
                    }
                    if (originalProxy.network === 'grpc' && originalProxy['grpc-opts']) {
                        cleanProxy['grpc-opts'] = originalProxy['grpc-opts'];
                    }
                    break;
                case 'trojan':
                    cleanProxy.password = originalProxy.password;
                    cleanProxy.tls = originalProxy.tls || false;
                    if (originalProxy.servername) cleanProxy.servername = originalProxy.servername;
                    if (originalProxy.alpn) cleanProxy.alpn = originalProxy.alpn;
                     if (originalProxy.network) cleanProxy.network = originalProxy.network;
                    if (originalProxy.network === 'ws' && originalProxy['ws-opts']) {
                        cleanProxy['ws-opts'] = originalProxy['ws-opts'];
                    }
                    if (originalProxy.network === 'grpc' && originalProxy['grpc-opts']) {
                        cleanProxy['grpc-opts'] = originalProxy['grpc-opts'];
                    }
                    break;
                case 'ss':
                    cleanProxy.cipher = originalProxy.cipher;
                    cleanProxy.password = originalProxy.password;
                    if (originalProxy.obfs) cleanProxy.obfs = originalProxy.obfs;
                    if (originalProxy.obfsHost) cleanProxy.obfsHost = originalProxy.obfsHost;
                    if (originalProxy.plugin) cleanProxy.plugin = originalProxy.plugin;
                    if (originalProxy.pluginOpts) cleanProxy.pluginOpts = originalProxy.pluginOpts;
                    break;
                case 'ssr':
                    cleanProxy.password = originalProxy.password;
                    cleanProxy.cipher = originalProxy.cipher;
                    if (originalProxy.obfs) cleanProxy.obfs = originalProxy.obfs;
                    if (originalProxy.protocol) cleanProxy.protocol = originalProxy.protocol;
                    if (originalProxy.obfsparam) cleanProxy.obfsParam = originalProxy.obfsparam;
                    if (originalProxy.protoparam) cleanProxy.protocolParam = originalProxy.protoparam;
                    break;
                case 'vmess':
                    cleanProxy.uuid = originalProxy.uuid;
                    cleanProxy.alterId = originalProxy.alterId || 0;
                    cleanProxy.cipher = originalProxy.cipher || 'auto';
                    cleanProxy.tls = originalProxy.tls || false;
                    if (originalProxy.servername) cleanProxy.servername = originalProxy.servername;
                    if (originalProxy.network) cleanProxy.network = originalProxy.network;
                    if (originalProxy.network === 'ws' && originalProxy['ws-opts']) {
                        cleanProxy['ws-opts'] = originalProxy['ws-opts'];
                    }
                    if (originalProxy.network === 'grpc' && originalProxy['grpc-opts']) {
                        cleanProxy['grpc-opts'] = originalProxy['grpc-opts'];
                    }
                    break;
                case 'hysteria':
                case 'hy':
                    cleanProxy.auth = originalProxy.auth;
                    cleanProxy.network = originalProxy.network || 'udp';
                    cleanProxy.tls = originalProxy.tls || false;
                    if (originalProxy.servername) cleanProxy.servername = originalProxy.servername;
                    if (originalProxy.alpn) cleanProxy.alpn = originalProxy.alpn;
                    if (originalProxy.ports) cleanProxy.ports = originalProxy.ports;
                    if (originalProxy.up) cleanProxy.up = originalProxy.up;
                    if (originalProxy.down) cleanProxy.down = originalProxy.down;
                    if (originalProxy.obfs) cleanProxy.obfs = originalProxy.obfs;
                    if (originalProxy.obfsParam) cleanProxy.obfsParam = originalProxy.obfsParam;
                    cleanProxy.fastOpen = originalProxy.fastOpen || false;
                    break;
                case 'hysteria2':
                case 'hy2':
                    cleanProxy.password = originalProxy.password;
                    cleanProxy.tls = originalProxy.tls || false;
                    if (originalProxy.servername) cleanProxy.servername = originalProxy.servername;
                    if (originalProxy.alpn) cleanProxy.alpn = originalProxy.alpn;
                    cleanProxy.fastOpen = originalProxy.fastOpen || false;
                    break;
                default:
                    // 对于不被识别的代理类型，但如果它们通过了测试，则尽量保留其原始信息
                    console.warn(`WARN: 代理 '${originalProxy.name}' 类型 '${originalProxy.type}' 未在可导入配置中完全映射。将尽可能保留原始字段。`);
                    return originalProxy; // 尝试返回原始代理对象
            }
            return cleanProxy;
        }
        return null; // 如果原始代理未找到，则跳过
    }).filter(p => p !== null); // 过滤掉 null 条目

    if (importableProxies.length === 0) {
        console.warn("\n没有发现任何成功的代理节点，跳过生成可导入的配置文件。");
    }

    // 构建可导入的 Clash 配置文件
    const importableClashConfig = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': importableProxies, // 仅包含成功的代理
        'proxy-groups': [
            {
                name: 'Proxy',
                type: 'select',
                proxies: importableProxies.map(p => p.name) // 引用所有成功的代理名称
            },
            {
                name: 'Fallback', // 备用组，当主代理失败时切换
                type: 'fallback',
                proxies: importableProxies.map(p => p.name),
                url: 'http://www.gstatic.com/generate_204',
                interval: 300 // 300秒检查一次
            },
            {
                name: 'Auto', // 自动选择最佳延迟
                type: 'url-test',
                proxies: importableProxies.map(p => p.name),
                url: 'http://www.gstatic.com/generate_204',
                interval: 300
            }
        ],
        'rules': [
            // 添加一些常用规则，你可以根据需要调整这些规则
            'DOMAIN-SUFFIX,google.com,Proxy',
            'DOMAIN-SUFFIX,youtube.com,Proxy',
            'DOMAIN-SUFFIX,netflix.com,Proxy',
            'DOMAIN-SUFFIX,facebook.com,Proxy',
            'DOMAIN-SUFFIX,twitter.com,Proxy',
            'DOMAIN-SUFFIX,wikipedia.org,Proxy',
            'GEOIP,CN,DIRECT', // 国内IP直连
            'MATCH,Proxy' // 其他流量走 Proxy 组
        ]
    };

    // 写入可导入的 Clash 配置文件到 data/521.yaml
    try {
        await fs.writeFile(outputConfigPath, yaml.dump(importableClashConfig, { lineWidth: -1 }), 'utf8');
        console.log(`\n已成功生成并写入可导入的 Clash 配置文件到 ${outputConfigPath}`);
    } catch (error) {
        console.error(`写入可导入配置文件到 ${outputConfigPath} 失败: ${error.message}`);
    }

    // 写入详细的测试报告到 data/521_detailed_report.yaml
    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        successful_proxies_count: successfulProxies.length,
        results: testResults // 包含所有代理的完整测试结果
    };
    try {
        await fs.writeFile(outputReportPath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`详细测试报告已写入 ${outputReportPath}`);
    } catch (error) {
        console.error(`写入详细测试报告失败: ${error.message}`);
    }

    return finalReport;
}

// --- 脚本执行 ---
// 当脚本直接执行时运行测试
if (require.main === module) {
    runNodeTests().then(() => console.log('所有测试过程已完成。')).catch(error => {
        console.error(`测试运行过程中发生未捕获错误:`, error);
        process.exit(1); // 退出并返回非零状态码表示失败
    });
}

