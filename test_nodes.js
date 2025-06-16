const fs = require('fs/promises'); // 用于异步文件操作
const yaml = require('js-yaml');   // 用于解析 YAML 文件
const path = require('path');     // 用于路径操作

// 辅助函数：测试延迟
async function testLatency(url, timeout = 5000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
        clearTimeout(id);
        if (response.ok) {
            return Date.now() - start;
        }
        return -1; // 失败
    } catch (error) {
        if (error.name === 'AbortError') {
            return `超时 (${timeout}ms)`;
        }
        return `错误: ${error.message.substring(0, 50)}...`; // 截断错误信息
    }
}

// 辅助函数：测试下载速度
async function testDownloadSpeed(url, sizeBytes = 1000000, timeout = 10000) { // 默认1MB，10秒超时
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

        const duration = (Date.now() - start) / 1000; // 秒
        if (duration === 0) return "计算错误 (持续时间为0)";
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration; // Mbps
        return `${speedMbps.toFixed(2)} Mbps (${(downloadedBytes / (1024 * 1024)).toFixed(2)} MB)`;
    } catch (error) {
        if (error.name === 'AbortError') {
            return `下载超时 (${timeout}ms)`;
        }
        return `下载测试异常: ${error.message.substring(0, 50)}...`;
    }
}

// 主测试函数
async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputFilePath = path.join(__dirname, 'data', '521.yaml');

    let proxiesConfig;
    try {
        const fileContent = await fs.readFile(inputFilePath, 'utf8');
        proxiesConfig = yaml.load(fileContent);
        // *** 关键修改：检查 proxies 数组而不是 nodes 数组 ***
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

    console.log(`开始测试 ${proxiesConfig.proxies.length} 个代理...`);
    const testResults = [];

    for (const proxy of proxiesConfig.proxies) { // *** 关键修改：遍历 proxies ***
        const nodeName = proxy.name || "未知名称";
        const serverAddress = proxy.server; // 获取代理的服务器地址
        const testUrl = `http://${serverAddress}:80`; // 默认使用 HTTP 80 端口测试连通性

        // 如果代理有 'tls: True' 或 'port' 等信息，可以尝试构建更精确的测试URL
        // 这里只是一个简单的示例，可能需要根据你的代理类型和端口进行调整
        // 例如，如果明确知道是 HTTPS 代理或 VLESS/Trojan 等需要特定端口和 TLS 的协议，可能需要构建一个更复杂的测试URL
        let testTargetUrl = testUrl;
        if (proxy.tls === true && proxy.port) {
            testTargetUrl = `https://${serverAddress}:${proxy.port}`;
        } else if (proxy.port) {
            testTargetUrl = `http://${serverAddress}:${proxy.port}`;
        }

        // 对于某些特殊的 servername，可能需要用 servername 来构造 URL
        if (proxy.servername) {
            // 这里只是一个简单的处理，可能不适用于所有情况
            // 更复杂的代理测试需要根据协议类型（vless, trojan等）构建对应的URL或使用专用工具
            if (proxy.tls === true && proxy.port) {
                 testTargetUrl = `https://${proxy.servername}:${proxy.port}`;
            } else if (proxy.port) {
                 testTargetUrl = `http://${proxy.servername}:${proxy.port}`;
            } else {
                 testTargetUrl = `http://${proxy.servername}`; // 默认HTTP 80
            }
        }

        console.log(`正在测试代理: ${nodeName} (目标: ${testTargetUrl})`);
        const result = {
            name: nodeName,
            server: serverAddress, // 记录原始服务器地址
            test_target_url: testTargetUrl, // 记录用于测试的 URL
            latency_ms: await testLatency(testTargetUrl),
            download_speed: "未测试"
        };

        // 如果测试URL看起来像一个下载链接，则进行下载测速
        if (testTargetUrl.includes('speed.cloudflare.com/__down') || testTargetUrl.includes('github.com/releases/download')) {
             // 从 URL 中提取下载字节数，如果没有则默认 1MB
            const bytesMatch = testTargetUrl.match(/bytes=(\d+)/);
            const downloadSizeBytes = bytesMatch ? parseInt(bytesMatch[1], 10) : 1000000;
            result.download_speed = await testDownloadSpeed(testTargetUrl, downloadSizeBytes);
        }
        
        testResults.push(result);
    }

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        results: testResults
    };

    try {
        // 将结果写入 521.yaml
        await fs.writeFile(outputFilePath, yaml.dump(finalReport), 'utf8');
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
        // console.log(JSON.stringify(results, null, 2)); // 可以打印最终结果到控制台
    }).catch(error => {
        console.error("运行测试时发生未捕获错误:", error);
        process.exit(1); // 退出并返回非零状态码表示失败
    });
}
