const fs = require('fs/promises'); // 用于异步文件操作
const yaml = require('js-yaml');    // 用于解析 YAML 文件
const path = require('path');       // 用于路径操作
const { PromisePool } = require('@supercharge/promise-pool'); // 用于控制并发
const { exec, spawn } = require('child_process'); // 用于启动/停止Clash进程
// const { setTimeout } = require('timers/promises'); // 已移除此行，使用全局的 setTimeout

const { ProxyAgent } = require('undici'); // 用于配置 fetch 使用代理

// --- 全局变量和辅助函数 ---

// 全局定义代理代理，在 main 函数中实例化
let globalProxyAgent;

// 辅助函数：测试延迟
async function testLatency(url, timeout = 5000) { // 默认超时 5 秒
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
            dispatcher: globalProxyAgent // <-- 使用全局代理
        });
        clearTimeout(timeoutId); // 清除超时计时器

        if (response.ok) {
            return Date.now() - start; // 返回延迟毫秒数
        } else {
            // 如果响应状态码不是 2xx，则返回错误状态码
            return `HTTP Error: ${response.status} ${response.statusText}`;
        }
    } catch (error) {
        // 确保清除可能存在的 timeoutId，以防错误在 clearTimeout 之前发生
        if (timeoutId) {
            clearTimeout(timeoutId);
        }

        if (error.name === 'AbortError') {
            return `超时 (${timeout}ms)`;
        } else if (error.cause && error.cause.code) { // 捕获更具体的网络错误码
            return `网络错误: ${error.cause.code}`;
        }
        return `连接错误: ${error.message.substring(0, 50)}...`; // 截断错误信息
    }
}

// 辅助函数：测试下载速度
async function testDownloadSpeed(url, sizeBytes = 1000000, timeout = 10000) { // 默认下载 1MB, 超时 10 秒
    const start = Date.now();
    let timeoutId;
    try {
        const controller = new AbortController();
        // 使用全局的 setTimeout 来设置 AbortController 的超时，并获取其返回的 ID
        timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            dispatcher: globalProxyAgent // <-- 使用全局代理
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            return `下载失败 (状态码: ${response.status})`;
        }

        const reader = response.body.getReader();
        let downloadedBytes = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            downloadedBytes += value.length;
            // 如果下载量超过预期，可以提前结束
            if (downloadedBytes >= sizeBytes) break;
        }

        const duration = (Date.now() - start) / 1000; // 转换为秒
        if (duration === 0) return "计算错误 (持续时间为0)";
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration; // Mbps
        return `${speedMbps.toFixed(2)} Mbps (${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB)`;
    } catch (error) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        if (error.name === 'AbortError') {
            return `下载超时 (${timeout}ms)`;
        } else if (error.cause && error.cause.code) {
            return `下载网络错误: ${error.cause.code}`;
        }
        return `下载测试异常: ${error.message.substring(0, 50)}...`;
    }
}

// 辅助函数：根据代理信息生成一个临时的 Clash 配置文件
function generateClashConfig(proxy) {
    const config = {
        'port': 7890, // Clash 监听的 HTTP 代理端口
        'socks-port': 7891, // Clash 监听的 SOCKS5 代理端口
        'allow-lan': false,
        'mode': 'rule', // 切换到规则模式，MATCH 规则才能生效
        'log-level': 'info', // 调试时设置为 info 或 debug，上线时可改为 silent
        'external-controller': '127.0.0.1:9090', // 可选，Clash 面板端口
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
        udp: proxy.udp || false, // 从 520.yaml 读取 udp: True/False
        'skip-cert-verify': proxy['skip-cert-verify'] || false, // 默认不跳过证书验证
    };

    // 根据代理类型添加特定参数
    switch (proxy.type.toLowerCase()) {
        case 'vless':
            clashProxy.uuid = proxy.uuid;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) { clashProxy.servername = proxy.servername; }
            if (proxy.alpn) { clashProxy.alpn = proxy.alpn; }
            // 根据 network 类型添加相应的 opts
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy.network = 'ws';
                clashProxy['ws-opts'] = {
                    path: proxy['ws-opts'].path || '/',
                    headers: proxy['ws-opts'].headers || {}
                };
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy.network = 'grpc'; // 确保 network 字段也设置
                clashProxy['grpc-opts'] = {
                    serviceName: proxy['grpc-opts'].serviceName || ''
                };
            }
            // 同样处理 h2-opts, http-opts 等，如果你的 520.yaml 中有这些字段
            break;
        case 'trojan':
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) { clashProxy.servername = proxy.servername; }
            if (proxy.alpn) { clashProxy.alpn = proxy.alpn; }
            // 同样处理 network 和相关 opts (ws-opts, grpc-opts, h2-opts)
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy.network = 'ws';
                clashProxy['ws-opts'] = {
                    path: proxy['ws-opts'].path || '/',
                    headers: proxy['ws-opts'].headers || {}
                };
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy.network = 'grpc';
                clashProxy['grpc-opts'] = {
                    serviceName: proxy['grpc-opts'].serviceName || ''
                };
            }
            break;
        case 'ss': // Shadowsocks
            clashProxy.cipher = proxy.cipher;
            clashProxy.password = proxy.password;
            clashProxy.obfs = proxy.obfs; // obfs type (e.g., tls, http)
            clashProxy.obfsHost = proxy.obfsHost; // obfs host
            clashProxy.plugin = proxy.plugin; // ss-plugin
            clashProxy.pluginOpts = proxy.pluginOpts; // plugin-opts
            break;
        case 'ssr': // ShadowsocksR (注意 Clash 对 SSR 支持可能不完全或需要 Clash.Meta)
            clashProxy.password = proxy.password;
            clashProxy.obfs = proxy.obfs;
            clashProxy.protocol = proxy.protocol;
            clashProxy.obfsParam = proxy.obfsparam;
            clashProxy.protocolParam = proxy.protoparam;
            clashProxy.cipher = proxy.cipher;
            break;
        case 'vmess':
            clashProxy.uuid = proxy.uuid;
            clashProxy.alterId = proxy.alterId || 0; // alterId 默认是 0
            clashProxy.cipher = proxy.cipher || 'auto'; // 加密方式，通常为 auto
            clashProxy.tls = proxy.tls || false;

            if (proxy.servername) { clashProxy.servername = proxy.servername; }
            if (proxy.network) { clashProxy.network = proxy.network; } // network (tcp, ws, http, h2, grpc)

            // 根据 network 类型添加相应的 opts
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy['ws-opts'] = {
                    path: proxy['ws-opts'].path || '/',
                    headers: proxy['ws-opts'].headers || {}
                };
            }
            if (proxy.network === 'grpc' && proxy['grpc-opts']) {
                clashProxy['grpc-opts'] = {
                    serviceName: proxy['grpc-opts'].serviceName || ''
                };
            }
            // 同样处理 h2-opts, http-opts 等，如果你的 520.yaml 中有这些字段
            break;
        case 'hysteria':
        case 'hy': // 你的 520.yaml 可能使用 'hy' 作为别名
            clashProxy.auth = proxy.auth; // 认证密码或密钥
            clashProxy.network = proxy.network || 'udp'; // Hysteria 默认为 UDP
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) { clashProxy.servername = proxy.servername; }
            if (proxy.alpn) { clashProxy.alpn = proxy.alpn; }
            if (proxy.ports) { clashProxy.ports = proxy.ports; } // Clash.Meta 的 Hysteria 配置中可能有端口范围，如 '443-445'
            if (proxy.up) { clashProxy.up = proxy.up; } // 上行带宽限制 (例如 '50mbps')
            if (proxy.down) { clashProxy.down = proxy.down; } // 下行带宽限制 (例如 '100mbps')
            if (proxy.obfs) { clashProxy.obfs = proxy.obfs; } // Hysteria 的混淆类型，例如 'salamander'
            if (proxy.obfsParam) { clashProxy.obfsParam = proxy.obfsParam; } // Hysteria 混淆参数
            clashProxy.fastOpen = proxy.fastOpen || false; // TCP Fast Open
            break;

        case 'hysteria2':
        case 'hy2': // 你的 520.yaml 可能使用 'hy2' 作为别名
            clashProxy.password = proxy.password; // Hysteria2 使用 password 字段
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) { clashProxy.servername = proxy.servername; }
            if (proxy.alpn) { clashProxy.alpn = proxy.alpn; }
            clashProxy.fastOpen = proxy.fastOpen || false;
            // Hysteria2 可能还有其他参数，如 enable-multiplex
            // if (proxy['enable-multiplex']) { clashProxy['enable-multiplex'] = proxy['enable-multiplex']; }
            break;

        default:
            console.warn(`未知或不支持的代理类型，可能无法正确配置 Clash: ${proxy.type}`);
            break;
    }

    config.proxies.push(clashProxy);
    config['proxy-groups'].push({
        name: 'Proxy',
        type: 'select',
        proxies: [proxyName] // 引用刚刚添加的代理
    });
    config.rules.push('MATCH,Proxy'); // 所有流量都走 Proxy 组

    return yaml.dump(config, { lineWidth: -1 });
}

// 主测试函数
async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputFilePath = path.join(__dirname, 'data', '521.yaml');

    // 读取和解析配置文件
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

    // 在主函数顶部初始化 globalProxyAgent，Clash 默认监听 HTTP 端口 7890
    globalProxyAgent = new ProxyAgent('http://127.0.0.1:7890');

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理，最大并发数 5 (通过 Clash 客户端)...`);

    // 使用 PromisePool 并行测试代理，限制最大并发数为1，因为每个代理需要独立的Clash实例
    const { results: testResults } = await PromisePool
        .for(proxiesConfig.proxies)
        .withConcurrency(5) // <-- 提高并发数量，可以尝试 5 或 10
        .process(async (proxy) => {
            const nodeName = proxy.name || "未知名称";
            // 使用 proxy.name 来生成唯一的配置文件名，替换非法字符
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFileName = `clash-config-${safeNodeName}.yaml`;
            const configFilePath = path.join(__dirname, 'temp', configFileName);
            const clashExecutablePath = path.join(__dirname, 'tools', 'clash'); // Clash 可执行文件路径

            let clashProcess = null; // 用于存储 Clash 进程对象
            let latency = "N/A";
            let downloadSpeed = "未测试";
            let status = "失败"; // 新增状态字段

            console.log(`\n--- 正在测试代理: ${nodeName} (类型: ${proxy.type}) ---`);

            let result = {
                name: nodeName,
                server: proxy.server, // 记录原始服务器地址
                port: proxy.port || (proxy.tls ? 443 : 80), // 记录端口
                type: proxy.type || "未知", // 记录代理类型
                test_target_url: 'https://www.google.com/generate_204', // 统一的测试目标 URL
                status: "未开始",
                latency_ms: "N/A",
                download_speed: "未测试"
            };

            try {
                // 确保 temp 目录存在
                await fs.mkdir(path.join(__dirname, 'temp'), { recursive: true });

                // 1. 生成 Clash 配置
                const clashConfigContent = generateClashConfig(proxy);
                await fs.writeFile(configFilePath, clashConfigContent, 'utf8');
                console.log(`  - 已生成 Clash 配置: ${configFileName}`);

                // 2. 启动 Clash 客户端
                clashProcess = spawn(clashExecutablePath, ['-f', configFilePath], {
                    detached: true, // 使子进程独立于父进程
                    stdio: 'ignore' // 忽略 stdout/stderr，避免日志爆炸。调试时可改为 'inherit'
                });

                clashProcess.unref(); // 允许 Node.js 进程在子进程结束后退出

                // 监听 Clash 进程的错误
                clashProcess.on('error', (err) => {
                    console.error(`  - Clash 进程错误 (${nodeName}): ${err.message}`);
                    status = `Clash启动错误: ${err.message.substring(0, 50)}...`;
                });

                clashProcess.on('exit', (code, signal) => {
                    if (code !== 0 && signal !== 'SIGTERM') { // SIGTERM 是我们手动发出的终止信号
                        console.warn(`  - Clash 进程异常退出 (${nodeName}): Code ${code}, Signal ${signal}`);
                        if (status === "未开始" || status === "失败") { // 如果之前没有更具体的失败原因
                            status = `Clash异常退出: Code ${code}`;
                        }
                    }
                });

                // 3. 等待 Clash 启动并初始化 (给它一些时间)
                // 使用 timers/promises 的 setTimeout，它返回一个 Promise，用于 await
                await require('timers/promises').setTimeout(5000); // 增加等待时间到 5 秒

                // 4. 执行实际的代理测试 (例如访问 Google 的无内容页面)
                // 使用一个稳定的、全球可访问的URL来测试代理功能
                const testUrlForProxy = 'https://www.google.com/generate_204'; // 无内容页面，只测连通性
                console.log(`  - 正在通过代理测试 ${nodeName} 连接到 ${testUrlForProxy}`);

                latency = await testLatency(testUrlForProxy);

                if (typeof latency === 'number') {
                    status = "成功";
                    console.log(`  - ${nodeName} 延迟: ${latency}ms`);

                    // 成功后才测速
                    // 你也可以在这里指定一个测速文件 URL，例如 Cloudflare 或某个 GitHub release
                    // downloadTestUrl = 'http://speedtest.tele2.net/10MB.zip'; // 一个稳定的10MB测试文件
                    // downloadSpeed = await testDownloadSpeed(downloadTestUrl, 10 * 1024 * 1024, 15000); // 10MB, 15秒超时
                    // console.log(`  - ${nodeName} 下载速度: ${downloadSpeed}`);
                } else {
                    status = `代理连接失败: ${latency}`; // latency 包含了错误字符串
                    console.log(`  - ${nodeName} 代理测试失败: ${latency}`);
                }

            } catch (testError) {
                // 捕获测试函数内部未处理的意外错误
                console.error(`  - 测试代理 ${nodeName} 时发生未捕获异常:`, testError.message);
                status = `未捕获异常: ${testError.message.substring(0, 50)}...`;
            } finally {
                // 5. 停止 Clash 客户端并清理临时文件
                if (clashProcess && !clashProcess.killed) { // 检查进程是否还在运行
                    try {
                        process.kill(clashProcess.pid, 'SIGTERM'); // 尝试发送 SIGTERM 信号
                        // 等待进程终止，给它一点时间
                        await require('timers/promises').setTimeout(1000); // 使用 timers/promises 的 setTimeout
                        console.log(`  - 已尝试停止 Clash 进程 (PID: ${clashProcess.pid})`);
                    } catch (killError) {
                        console.warn(`  - 无法终止 Clash 进程 ${clashProcess.pid}:`, killError.message);
                    }
                }
                try {
                    await fs.unlink(configFilePath); // 删除临时配置文件
                    console.log(`  - 已删除临时配置文件: ${configFileName}`);
                } catch (unlinkError) {
                    console.warn(`  - 无法删除临时配置文件 ${configFilePath}:`, unlinkError.message);
                }
            }

            // 更新最终结果对象
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

    // 写入结果到 521.yaml
    try {
        await fs.writeFile(outputFilePath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`\n测试结果已成功写入 ${outputFilePath}`);
    } catch (error) {
        console.error(`写入 521.yaml 失败: ${error.message}`);
    }

    return finalReport;
}

// 当脚本直接执行时运行测试
if (require.main === module) {
    runNodeTests().then(results => {
        console.log("\n--- 测试完成 ---");
        // console.log(JSON.stringify(results, null, 2)); // 调试时可开启
    }).catch(error => {
        console.error("运行测试时发生未捕获错误:", error);
        process.exit(1); // 退出并返回非零状态码表示失败
    });
}
