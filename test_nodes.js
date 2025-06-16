const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool'); // 用于控制并发

// 辅助函数：测试延迟
async function testLatency(url, timeout = 5000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
        clearTimeout(id);
        return response.ok ? Date.now() - start : -1;
    } catch (error) {
        return error.name === 'AbortError' ? `超时 (${timeout}ms)` : `错误: ${error.message.slice(0, 50)}...`;
    }
}

// 辅助函数：测试下载速度
async function testDownloadSpeed(url, sizeBytes = 1000000, timeout = 10000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, { method: 'GET', signal: controller.signal });
        clearTimeout(id);

        if (!response.ok) return `下载失败 (状态码: ${response.status})`;

        const reader = response.body.getReader();
        let downloadedBytes = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done || downloadedBytes >= sizeBytes) break;
            downloadedBytes += value.length;
        }

        const duration = (Date.now() - start) / 1000;
        if (duration === 0) return "计算错误 (持续时间为0)";
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration;
        return `${speedMbps.toFixed(2)} Mbps (${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB)`;
    } catch (error) {
        return error.name === 'AbortError' ? `下载超时 (${timeout}ms)` : `下载测试异常: ${error.message.slice(0, 50)}...`;
    }
}

// 辅助函数：构建测试URL
function buildTestUrl(proxy) {
    const server = proxy.servername || proxy.server;
    const port = proxy.port || 80;
    const protocol = proxy.tls ? 'https' : 'http';
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
        return { timestamp: new Date().toISOString(), error: `读取或解析 520.yaml 失败: ${error.message}` };
    }

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理...`);

    // 并行测试代理，限制最大并发数为10
    const { results: testResults } = await PromisePool
        .for(proxiesConfig.proxies)
        .withConcurrency(10)
        .process(async (proxy) => {
            const nodeName = proxy.name || "未知名称";
            const testUrl = buildTestUrl(proxy);
            console.log(`正在测试代理: ${nodeName} (目标: ${testUrl})`);

            const result = {
                name: nodeName,
                server: proxy.server,
                test_target_url: testUrl,
                latency_ms: await testLatency(testUrl),
                download_speed: "未测试"
            };

            // 仅对特定URL进行下载测速
            if (testUrl.includes('speed.cloudflare.com/__down') || testUrl.includes('github.com/releases/download')) {
                const bytesMatch = testUrl.match(/bytes=(\d+)/);
                const downloadSizeBytes = bytesMatch ? parseInt(bytesMatch[1], 10) : 1000000;
                result.download_speed = await testDownloadSpeed(testUrl, downloadSizeBytes);
            }

            return result;
        });

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        results: testResults
    };

    // 写入结果
    try {
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
    }).catch(error => {
        console.error("运行测试时发生未捕获错误:", error);
        process.exit(1);
    });
}
