const fs = require('fs/promises'); // 用于异步文件操作
const yaml = require('js-yaml');   // 用于解析 YAML 文件
const path = require('path');     // 用于路径操作
const { PromisePool } = require('@supercharge/promise-pool'); // 用于控制并发

// 辅助函数：测试延迟
async function testLatency(url, timeout = 5000) { // 默认超时 5 秒
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout); // 设置 AbortController 的超时
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
        clearTimeout(id); // 清除超时计时器

        if (response.ok) {
            return Date.now() - start; // 返回延迟毫秒数
        } else {
            // 如果响应状态码不是 2xx，则返回错误状态码
            return `HTTP Error: ${response.status} ${response.statusText}`;
        }
    } catch (error) {
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
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, { method: 'GET', signal: controller.signal });
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
            // 如果下载量超过预期，可以提前结束
            if (downloadedBytes >= sizeBytes) break;
        }

        const duration = (Date.now() - start) / 1000; // 转换为秒
        if (duration === 0) return "计算错误 (持续时间为0)";
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration; // Mbps
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

// 辅助函数：更智能地构建测试URL
function buildTestUrl(proxy) {
    // 优先使用 servername，如果没有则回退到 server
    const server = proxy.servername || proxy.server;
    // 优先使用代理中指定的端口，如果没有则根据 TLS 决定默认端口
    const port = proxy.port || (proxy.tls ? 443 : 80);
    // 根据 TLS 决定协议
    const protocol = proxy.tls ? 'https' : 'http';

    // 简单构建 URL，注意这仍是基础的HTTP/HTTPS测试，不适用于所有代理协议
    return `${protocol}://${server}:${port}`;
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

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理，最大并发数 10...`);

    // 使用 PromisePool 并行测试代理，限制最大并发数为10
    const { results: testResults } = await PromisePool
        .for(proxiesConfig.proxies)
        .withConcurrency(10) // <-- 设置并发数量
        .process(async (proxy) => {
            const nodeName = proxy.name || "未知名称";
            const testUrl = buildTestUrl(proxy);
            console.log(`正在测试代理: ${nodeName} (目标: ${testUrl})`);

            let latency = "未测试";
            let downloadSpeed = "未测试";
            let status = "失败"; // 新增状态字段

            try {
                latency = await testLatency(testUrl);
                if (typeof latency === 'number' && latency !== -1) {
                    status = "成功"; // 延迟测试成功
                } else {
                    status = "延迟测试失败";
                }

                // 仅对特定URL进行下载测速
                if (testUrl.includes('speed.cloudflare.com/__down') || testUrl.includes('github.com/releases/download')) {
                    // 可以调整下载文件大小或超时，例如 downloadSizeBytes: 500000 (0.5MB), timeout: 8000
                    const bytesMatch = testUrl.match(/bytes=(\d+)/);
                    const downloadSizeBytes = bytesMatch ? parseInt(bytesMatch[1], 10) : 500000; // 默认 0.5MB
                    downloadSpeed = await testDownloadSpeed(testUrl, downloadSizeBytes, 8000); // 超时 8 秒
                }
            } catch (testError) {
                // 捕获测试函数内部未处理的意外错误
                console.error(`测试代理 ${nodeName} 时发生异常:`, testError.message);
                status = `异常: ${testError.message.substring(0, 50)}...`;
            }

            return {
                name: nodeName,
                server: proxy.server, // 记录原始服务器地址
                port: proxy.port || (proxy.tls ? 443 : 80), // 记录端口
                type: proxy.type || "未知", // 记录代理类型
                test_target_url: testUrl,
                status: status, // 新增状态字段
                latency_ms: latency,
                download_speed: downloadSpeed
                // 如果需要，可以添加更多原始代理信息，但要避免敏感信息，如 uuid, password
            };
        });

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        results: testResults
    };

    // 写入结果到 521.yaml
    try {
        // 使用 { lineWidth: -1 } 避免长行被折叠，保持 YAML 清晰
        await fs.writeFile(outputFilePath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`测试结果已成功写入 ${outputFilePath}`);
    } catch (error) {
        console.error(`写入 521.yaml 失败: ${error.message}`);
    }

    return finalReport;
}

// 当脚本直接执行时运行测试
if (require.main === module) {
    runNodeTests().then(results => {
        console.log("\n--- 测试完成 ---");
        // 如果想在本地运行时看到完整的 JSON 结果，可以取消下面这行的注释
        // console.log(JSON.stringify(results, null, 2));
    }).catch(error => {
        console.error("运行测试时发生未捕获错误:", error);
        process.exit(1); // 退出并返回非零状态码表示失败
    });
}
