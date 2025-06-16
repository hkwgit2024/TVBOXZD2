const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool');
const { spawn } = require('child_process');
const { setTimeout, clearTimeout } = require('timers');
const { ProxyAgent } = require('undici');

async function testLatency(url, timeout = 5000, proxyAgent) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal,
            dispatcher: proxyAgent
        });
        clearTimeout(id);

        if (response.ok) {
            return Date.now() - start;
        } else {
            return `HTTP Error: ${response.status} ${response.statusText}`;
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            return `超时 (${timeout}ms)`;
        } else if (error.cause && error.cause.code) {
            return `网络错误: ${error.cause.code}`;
        }
        return `连接错误: ${error.message.substring(0, 50)}...`;
    }
}

async function checkClashReady(controllerUrl, timeout = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        try {
            const response = await fetch(controllerUrl, { method: 'GET', timeout: 500 });
            if (response.ok) return true;
        } catch {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    return false;
}

function generateClashConfig(proxy, basePort = 7890) {
    const config = {
        port: basePort,
        'socks-port': basePort + 1,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': `127.0.0.1:${basePort + 2}`,
        proxies: [],
        'proxy-groups': [],
        rules: []
    };

    const proxyName = proxy.name || `proxy-${Math.random().toString(36).substring(7)}`;
    let clashProxy = {
        name: proxyName,
        type: proxy.type.toLowerCase() === 'hy' ? 'hysteria' : proxy.type.toLowerCase() === 'hy2' ? 'hysteria2' : proxy.type,
        server: proxy.server,
        port: proxy.port,
        udp: proxy.udp ?? true,
        'skip-cert-verify': proxy['skip-cert-verify'] ?? false,
    };

    switch (clashProxy.type.toLowerCase()) {
        case 'vless':
            clashProxy.uuid = proxy.uuid;
            clashProxy.tls = proxy.tls ?? false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            if (proxy['ws-opts']) {
                clashProxy.network = 'ws';
                clashProxy['ws-opts'] = {
                    path: proxy['ws-opts'].path || '/',
                    headers: proxy['ws-opts'].headers || {}
                };
            }
            break;
        case 'trojan':
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls ?? false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            break;
        case 'ss':
            clashProxy.cipher = proxy.cipher;
            clashProxy.password = proxy.password;
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            if (proxy.obfsHost) clashProxy.obfsHost = proxy.obfsHost;
            if (proxy.plugin) clashProxy.plugin = proxy.plugin;
            if (proxy.pluginOpts) clashProxy.pluginOpts = proxy.pluginOpts;
            break;
        case 'ssr':
            clashProxy.password = proxy.password;
            clashProxy.obfs = proxy.obfs;
            clashProxy.protocol = proxy.protocol;
            clashProxy.obfsParam = proxy.obfsparam;
            clashProxy.protocolParam = proxy.protoparam;
            clashProxy.cipher = proxy.cipher;
            break;
        case 'vmess':
            clashProxy.uuid = proxy.uuid;
            clashProxy.alterId = proxy.alterId || 0;
            clashProxy.cipher = proxy.cipher || 'auto';
            clashProxy.tls = proxy.tls ?? false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy['ws-opts']) {
                clashProxy.network = 'ws';
                clashProxy['ws-opts'] = {
                    path: proxy['ws-opts'].path || '/',
                    headers: proxy['ws-opts'].headers || {}
                };
            }
            break;
        case 'hysteria':
            clashProxy.auth = proxy.auth || proxy.password;
            clashProxy.up = proxy.up || '10 Mbps';
            clashProxy.down = proxy.down || '100 Mbps';
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            clashProxy.protocol = proxy.protocol || 'udp';
            clashProxy.tls = proxy.tls ?? true;
            if (proxy.sni) clashProxy.sni = proxy.sni;
            if (proxy.ports) clashProxy.ports = proxy.ports;
            break;
        case 'hysteria2':
            clashProxy.password = proxy.auth || proxy.password;
            if (proxy.up) clashProxy.up = proxy.up;
            if (proxy.down) clashProxy.down = proxy.down;
            if (proxy.obfs) {
                clashProxy.obfs = {
                    type: proxy.obfs.type || 'salamander',
                    password: proxy.obfs.password
                };
            }
            clashProxy.tls = proxy.tls ?? true;
            if (proxy.sni) clashProxy.sni = proxy.sni;
            break;
        default:
            console.warn(`未知或不支持的代理类型: ${proxy.type}`);
            return null;
    }

    config.proxies.push(clashProxy);
    config['proxy-groups'].push({
        name: 'Proxy',
        type: 'select',
        proxies: [proxyName]
    });
    config.rules.push('MATCH,Proxy');
    return { config: yaml.dump(config, { lineWidth: -1 }), proxy: clashProxy };
}

async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputFilePath = path.join(__dirname, 'data', '521.yaml');

    let proxiesConfig;
    try {
        const fileContent = await fs.readFile(inputFilePath, 'utf8');
        proxiesConfig = yaml.load(fileContent);
        if (!proxiesConfig || !Array.isArray(proxiesConfig.proxies)) {
            throw new Error('520.yaml 文件格式不正确，缺少 "proxies" 数组');
        }
    } catch (error) {
        console.error(`读取或解析 520.yaml 失败: ${error.message}`);
        return {
            timestamp: new Date().toISOString(),
            error: `读取或解析 520.yaml 失败: ${error.message}`
        };
    }

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理，最大并发数 2...`);

    const { results: testResults } = await PromisePool
        .for(proxiesConfig.proxies)
        .withConcurrency(5)
        .process(async (proxy, index) => {
            const basePort = 7890 + (index % 2) * 2;
            const nodeName = proxy.name || `node_${index}`;
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFileName = `clash-config-${safeNodeName}-${basePort}.yaml`;
            const configFilePath = path.join(__dirname, 'temp', configFileName);
            const clashExecutablePath = path.join(__dirname, 'tools', 'clash');

            let clashProcess = null;
            let latency = 'N/A';
            let downloadSpeed = '未测试';
            let status = '失败';

            console.log(`\n--- 正在测试代理: ${nodeName} (类型: ${proxy.type}) ---`);

            let result = {
                name: nodeName,
                server: proxy.server,
                port: proxy.port || (proxy.tls ? 443 : 80),
                type: proxy.type || '未知',
                test_target_url: 'http://captive.apple.com',
                status: '未开始',
                latency_ms: 'N/A',
                download_speed: '未测试',
                originalProxy: proxy // 保留原始配置
            };

            try {
                await fs.mkdir(path.join(__dirname, 'temp'), { recursive: true });

                const clashConfigResult = generateClashConfig(proxy, basePort);
                if (!clashConfigResult) {
                    status = `不支持的代理类型: ${proxy.type}`;
                    result.status = status;
                    return result;
                }

                const { config: clashConfigContent, proxy: clashProxy } = clashConfigResult;
                await fs.writeFile(configFilePath, clashConfigContent, 'utf8');
                console.log(`  - 已生成 Clash 配置: ${configFileName}`);

                clashProcess = spawn(clashExecutablePath, ['-f', configFilePath], {
                    detached: true,
                    stdio: ['ignore', 'pipe', 'pipe']
                });

                clashProcess.unref();

                let clashError = '';
                clashProcess.stderr.on('data', (data) => {
                    clashError += data.toString();
                });

                clashProcess.on('error', (err) => {
                    console.error(`  - Clash 进程错误 (${nodeName}): ${err.message}`);
                    status = `Clash启动错误: ${err.message.substring(0, 50)}...`;
                });

                clashProcess.on('exit', (code, signal) => {
                    if (code !== 0 && signal !== 'SIGTERM' && signal !== 'SIGKILL') {
                        console.warn(`  - Clash 进程异常退出 (${nodeName}): Code ${code}, Signal ${signal}`);
                        if (status === '未开始' || status === '失败') {
                            status = `Clash异常退出: ${clashError.substring(0, 100)}...`;
                        }
                    }
                });

                const controllerUrl = `http://127.0.0.1:${basePort + 2}/version`;
                if (!(await checkClashReady(controllerUrl))) {
                    throw new Error('Clash 启动超时');
                }

                console.log(`  - Clash 启动成功 on port ${basePort}`);

                const proxyAgent = new ProxyAgent(`http://127.0.0.1:${basePort}`);
                const testUrlForProxy = 'http://captive.apple.com';
                console.log(`  - 测试 ${nodeName} 连接到 ${testUrlForProxy}`);

                latency = await testLatency(testUrlForProxy, 5000, proxyAgent);

                if (typeof latency === 'number') {
                    status = '成功';
                    console.log(`  - ${nodeName} 延迟: ${latency}ms`);
                    result.clashProxy = clashProxy; // 保存生成的 Clash 代理配置
                } else {
                    status = `代理连接失败: ${latency}`;
                    console.log(`  - ${nodeName} 代理测试失败: ${latency}`);
                }
            } catch (error) {
                console.error(`  - 测试 ${nodeName} 失败: ${error.message}`);
                status = `测试异常: ${error.message.substring(0, 50)}...`;
            } finally {
                if (clashProcess && !clashProcess.killed) {
                    try {
                        process.kill(clashProcess.pid, 'SIGTERM');
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        if (!clashProcess.killed) {
                            process.kill(clashProcess.pid, 'SIGKILL');
                            console.log(`  - 强制终止 Clash 进程 (PID: ${clashProcess.pid})`);
                        } else {
                            console.log(`  - 已停止 Clash 进程 (PID: ${clashProcess.pid})`);
                        }
                    } catch (killError) {
                        console.warn(`  - 无法终止 Clash 进程 ${clashProcess.pid}: ${killError.message}`);
                    }
                }
                try {
                    await fs.unlink(configFilePath);
                    console.log(`  - 已删除配置文件: ${configFileName}`);
                } catch (unlinkError) {
                    console.warn(`  - 无法删除配置文件 ${configFilePath}: ${unlinkError.message}`);
                }
            }

            result.status = status;
            result.latency_ms = latency;
            result.download_speed = downloadSpeed;
            return result;
        });

    // 生成客户端可用的配置文件
    const successfulProxies = testResults
        .filter(result => result.status === '成功' && result.clashProxy)
        .map(result => ({
            ...result.clashProxy,
            name: `${result.name} (${result.latency_ms}ms)` // 添加延迟到名称
        }));

    const clientConfig = {
        port: 7890,
        'socks-port': 7891,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        proxies: successfulProxies,
        'proxy-groups': [
            {
                name: 'Proxy',
                type: 'select',
                proxies: successfulProxies.map(proxy => proxy.name)
            },
            {
                name: 'Auto',
                type: 'url-test',
                proxies: successfulProxies.map(proxy => proxy.name),
                url: 'http://www.gstatic.com/generate_204',
                interval: 300
            }
        ],
        rules: [
            'DOMAIN-SUFFIX,google.com,Proxy',
            'DOMAIN-SUFFIX,netflix.com,Proxy',
            'GEOIP,CN,DIRECT',
            'MATCH,Proxy'
        ]
    };

    try {
        await fs.writeFile(outputFilePath, yaml.dump(clientConfig, { lineWidth: -1 }), 'utf8');
        console.log(`\n成功节点 (${successfulProxies.length}) 已写入 ${outputFilePath}`);
    } catch (error) {
        console.error(`写入 521.yaml 失败: ${error.message}`);
    }

    return {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        successful_count: successfulProxies.length,
        results: testResults
    };
}

if (require.main === module) {
    runNodeTests().then(results => {
        console.log('\n--- 测试完成 ---');
        console.log(`成功节点: ${results.successful_count}/${results.tested_proxies_count}`);
    }).catch(error => {
        console.error('运行测试失败:', error);
        process.exit(1);
    });
}
