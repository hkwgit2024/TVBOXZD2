const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool');
const { exec, spawn } = require('child_process');
const { setTimeout, clearTimeout } = require('timers'); // 使用传统 setTimeout 和 clearTimeout
const { ProxyAgent } = require('undici');

let globalProxyAgent;

async function testLatency(url, timeout = 5000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => {
            controller.abort();
        }, timeout);
        const response = await fetch(url, {
            method: 'HEAD',
            redirect: 'follow',
            signal: controller.signal,
            dispatcher: globalProxyAgent
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

async function testDownloadSpeed(url, sizeBytes = 1000000, timeout = 10000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            dispatcher: globalProxyAgent
        });
        clearTimeout(id);

        if (!response.ok) {
            return `下载失败 (状态码: ${response.status})`;
        }

        const reader = response.body.getReader();
        let downloadedBytes = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            downloadedBytes += value.length;
            if (downloadedBytes >= sizeBytes) break;
        }

        const duration = (Date.now() - start) / 1000;
        if (duration === 0) return "计算错误 (持续时间为0)";
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration;
        return `${speedMbps.toFixed(2)} Mbps (${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB)`;
    } catch (error) {
        if (error.name === 'AbortError') {
            return `下载超时 (${timeout}ms)`;
        } else if (error.cause && error.cause.code) {
            return `下载网络错误: ${error.cause.code}`;
        }
        return `下载测试异常: ${error.message.substring(0, 50)}...`;
    }
}

function generateClashConfig(proxy) {
    const config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': [],
        'proxy-groups': [],
        'rules': []
    };

    const proxyName = proxy.name || `proxy-${Math.random().toString(36).substring(7)}`;

    let clashProxy = {
        name: proxyName,
        type: proxy.type,
        server: proxy.server,
        port: proxy.port,
        udp: proxy.udp || false,
        'skip-cert-verify': proxy['skip-cert-verify'] || false,
    };

    switch (proxy.type.toLowerCase()) {
        case 'vless':
            clashProxy.uuid = proxy.uuid;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) {
                clashProxy.servername = proxy.servername;
            }
            if (proxy.alpn) {
                clashProxy.alpn = proxy.alpn;
            }
            break;
        case 'trojan':
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) {
                clashProxy.servername = proxy.servername;
            }
            if (proxy.alpn) {
                clashProxy.alpn = proxy.alpn;
            }
            break;
        case 'ss':
            clashProxy.cipher = proxy.cipher;
            clashProxy.password = proxy.password;
            clashProxy.obfs = proxy.obfs;
            clashProxy.obfsHost = proxy.obfsHost;
            clashProxy.plugin = proxy.plugin;
            clashProxy.pluginOpts = proxy.pluginOpts;
            break;
        case 'ssr':
            clashProxy.password = proxy.password;
            clashProxy.obfs = proxy.obfs;
            clashProxy.protocol = proxy.protocol;
            clashProxy.obfsParam = proxy.obfsparam;
            clashProxy.protocolParam = proxy.protoparam;
            clashProxy.cipher = proxy.cipher;
            break;
        default:
            console.warn(`未知或不支持的代理类型，可能无法正确配置 Clash: ${proxy.type}`);
            break;
    }

    config.proxies.push(clashProxy);
    config['proxy-groups'].push({
        name: 'Proxy',
        type: 'select',
        proxies: [proxyName]
    });
    config.rules.push('MATCH,Proxy');

    return yaml.dump(config, { lineWidth: -1 });
}

async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputFilePath = path.join(__dirname, 'data', '521.yaml');

    let proxiesConfig;
    try {
        const fileContent = await fs.readFile(inputFilePath, 'utf8');
        proxiesConfig = yaml.load(fileContent);
        if (!proxiesConfig || !Array.isArray(proxiesConfig.proxies)) {
            throw new Error('520.yaml 文件格式不正确，缺少 "proxies" 数组。');
        }
    } catch (error) {
        console.error(`读取或解析 520.yaml 失败: ${error.message}`);
        return {
            timestamp: new Date().toISOString(),
            error: `读取或解析 520.yaml 失败: ${error.message}`
        };
    }

    globalProxyAgent = new ProxyAgent('http://127.0.0.1:7890');

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理，最大并发数 1 (通过 Clash 客户端)...`);

    const { results: testResults } = await PromisePool
        .for(proxiesConfig.proxies)
        .withConcurrency(1)
        .process(async (proxy) => {
            const nodeName = proxy.name || "未知名称";
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFileName = `clash-config-${safeNodeName}.yaml`;
            const configFilePath = path.join(__dirname, 'temp', configFileName);
            const clashExecutablePath = path.join(__dirname, 'tools', 'clash');

            let clashProcess = null;
            let latency = "N/A";
            let downloadSpeed = "未测试";
            let status = "失败";

            console.log(`\n--- 正在测试代理: ${nodeName} (类型: ${proxy.type}) ---`);

            let result = {
                name: nodeName,
                server: proxy.server,
                port: proxy.port || (proxy.tls ? 443 : 80),
                type: proxy.type || "未知",
                test_target_url: 'https://www.google.com/generate_204',
                status: "未开始",
                latency_ms: "N/A",
                download_speed: "未测试"
            };

            try {
                await fs.mkdir(path.join(__dirname, 'temp'), { recursive: true });

                const clashConfigContent = generateClashConfig(proxy);
                await fs.writeFile(configFilePath, clashConfigContent, 'utf8');
                console.log(`  - 已生成 Clash 配置: ${configFileName}`);

                clashProcess = spawn(clashExecutablePath, ['-f', configFilePath], {
                    detached: true,
                    stdio: 'ignore'
                });

                clashProcess.unref();

                clashProcess.on('error', (err) => {
                    console.error(`  - Clash 进程错误 (${nodeName}): ${err.message}`);
                    status = `Clash启动错误: ${err.message.substring(0, 50)}...`;
                });

                clashProcess.on('exit', (code, signal) => {
                    if (code !== 0 && signal !== 'SIGTERM') {
                        console.warn(`  - Clash 进程异常退出 (${nodeName}): Code ${code}, Signal ${signal}`);
                        if (status === "未开始" || status === "失败") {
                            status = `Clash异常退出: Code ${code}`;
                        }
                    }
                });

                await new Promise(resolve => setTimeout(resolve, 5000)); // 使用传统 setTimeout 包装 Promise

                const testUrlForProxy = 'https://www.google.com/generate_204';
                console.log(`  - 正在通过代理测试 ${nodeName} 连接到 ${testUrlForProxy}`);

                latency = await testLatency(testUrlForProxy, 5000); // 显式传递 timeout

                if (typeof latency === 'number') {
                    status = "成功";
                    console.log(`  - ${nodeName} 延迟: ${latency}ms`);
                } else {
                    status = `代理连接失败: ${latency}`;
                    console.log(`  - ${nodeName} 代理测试失败: ${latency}`);
                }

            } catch (testError) {
                console.error(`  - 测试代理 ${nodeName} 时发生未捕获异常:`, testError.message);
                status = `未捕获异常: ${testError.message.substring(0, 50)}...`;
            } finally {
                if (clashProcess && !clashProcess.killed) {
                    try {
                        process.kill(clashProcess.pid, 'SIGTERM');
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        console.log(`  - 已尝试停止 Clash 进程 (PID: ${clashProcess.pid})`);
                    } catch (killError) {
                        console.warn(`  - 无法终止 Clash 进程 ${clashProcess.pid}:`, killError.message);
                    }
                }
                try {
                    await fs.unlink(configFilePath);
                    console.log(`  - 已删除临时配置文件: ${configFileName}`);
                } catch (unlinkError) {
                    console.warn(`  - 无法删除临时配置文件 ${configFilePath}:`, unlinkError.message);
                }
            }

            result.status = status;
            result.latency_ms = latency;
            result.download_speed = downloadSpeed;
            return result;
        });

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        results: testResults
    };

    try {
        await fs.writeFile(outputFilePath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`\n测试结果已成功写入 ${outputFilePath}`);
    } catch (error) {
        console.error(`写入 521.yaml 失败: ${error.message}`);
    }

    return finalReport;
}

if (require.main === module) {
    runNodeTests().then(results => {
        console.log("\n--- 测试完成 ---");
    }).catch(error => {
        console.error("运行测试时发生未捕获错误:", error);
        process.exit(1);
    });
}
