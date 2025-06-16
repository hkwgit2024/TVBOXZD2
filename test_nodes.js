const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool');
const { spawn } = require('child_process');
const { setTimeout, clearTimeout } = require('timers');
const { ProxyAgent } = require('undici');

async function testLatency(url, timeout = 3000, proxyAgent) {
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
        return response.ok ? Date.now() - start : `HTTP Error: ${response.status}`;
    } catch (error) {
        if (error.name === 'AbortError') return `Timeout (${timeout}ms)`;
        return error.cause?.code ? `Network Error: ${error.cause.code}` : `Error: ${error.message.substring(0, 50)}`;
    }
}

function generateClashConfig(proxy, port = 7890) {
    if (!proxy.server || !proxy.port || !proxy.type) {
        throw new Error('Invalid proxy config: missing server, port, or type');
    }

    const config = {
        port,
        'socks-port': port + 1,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'error',
        'external-controller': `127.0.0.1:${port + 2}`,
        proxies: [],
        'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: [] }],
        rules: ['MATCH,Proxy']
    };

    const proxyName = proxy.name || `proxy-${Math.random().toString(36).substring(7)}`;
    let clashProxy = {
        name: proxyName,
        type: proxy.type.toLowerCase(),
        server: proxy.server,
        port: proxy.port,
        udp: proxy.udp || false,
        'skip-cert-verify': proxy['skip-cert-verify'] || true
    };

    switch (proxy.type.toLowerCase()) {
        case 'vless':
            if (!proxy.uuid) throw new Error('VLESS requires uuid');
            clashProxy.uuid = proxy.uuid;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            break;
        case 'trojan':
            if (!proxy.password) throw new Error('Trojan requires password');
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            break;
        case 'ss':
            if (!proxy.cipher || !proxy.password) throw new Error('SS requires cipher and password');
            clashProxy.cipher = proxy.cipher;
            clashProxy.password = proxy.password;
            break;
        case 'vmess':
            if (!proxy.uuid) throw new Error('VMess requires uuid');
            clashProxy.uuid = proxy.uuid;
            clashProxy.alterId = proxy.alterId || 0;
            clashProxy.cipher = proxy.cipher || 'auto';
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy['ws-opts']) {
                clashProxy.network = 'ws';
                clashProxy['ws-opts'] = proxy['ws-opts'];
            }
            break;
        default:
            throw new Error(`Unsupported proxy type: ${proxy.type}`);
    }

    config.proxies.push(clashProxy);
    config['proxy-groups'][0].proxies.push(proxyName);
    return yaml.dump(config, { lineWidth: -1 });
}

async function checkClashReady(port, retries = 5, delay = 500) {
    for (let i = 0; i < retries; i++) {
        try {
            const response = await fetch(`http://127.0.0.1:${port + 2}/version`);
            if (response.ok) return true;
        } catch {}
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    return false;
}

async function killClashProcess(pid, port) {
    try {
        process.kill(pid, 'SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 500));
        const { exec } = require('child_process');
        await new Promise(resolve => exec(`lsof -ti :${port} | xargs kill -9 2>/dev/null`, resolve));
    } catch (error) {
        if (error.code !== 'ESRCH') console.warn(`Failed to kill PID ${pid}: ${error.message}`);
    }
}

async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputFilePath = path.join(__dirname, 'data', '521.yaml');
    const basePorts = [7890, 7894, 7898, 7902]; // 4 concurrent ports
    const testUrl = 'http://captive.apple.com'; // Stable test endpoint

    let proxiesConfig;
    try {
        const fileContent = await fs.readFile(inputFilePath, 'utf8');
        proxiesConfig = yaml.load(fileContent);
        if (!proxiesConfig?.proxies?.length) throw new Error('Invalid 520.yaml: no proxies found');
    } catch (error) {
        console.error(`Failed to read 520.yaml: ${error.message}`);
        return { timestamp: new Date().toISOString(), error: error.message };
    }

    // Pre-filter invalid proxies
    const invalidDomains = ['russia.com', 'singapore.com', 'japan.com', 'malaysia.com'];
    const validProxies = proxiesConfig.proxies.filter(proxy => {
        if (!proxy.server || !proxy.port || !proxy.type) {
            console.warn(`Skipping proxy ${proxy.name}: missing server, port, or type`);
            return false;
        }
        if (invalidDomains.includes(proxy.server)) {
            console.warn(`Skipping proxy ${proxy.name}: invalid server domain`);
            return false;
        }
        if (proxy.type.toLowerCase() === 'vless' && !proxy.uuid) {
            console.warn(`Skipping proxy ${proxy.name}: VLESS missing uuid`);
            return false;
        }
        if (proxy.type.toLowerCase() === 'trojan' && !proxy.password) {
            console.warn(`Skipping proxy ${proxy.name}: Trojan missing password`);
            return false;
        }
        if (proxy.type.toLowerCase() === 'ss' && (!proxy.cipher || !proxy.password)) {
            console.warn(`Skipping proxy ${proxy.name}: SS missing cipher or password`);
            return false;
        }
        if (proxy.type.toLowerCase() === 'vmess' && !proxy.uuid) {
            console.warn(`Skipping proxy ${proxy.name}: VMess missing uuid`);
            return false;
        }
        return true;
    });

    console.log(`Testing ${validProxies.length} proxies with concurrency 4...`);

    const { results: testResults } = await PromisePool
        .for(validProxies)
        .withConcurrency(4)
        .process(async (proxy, index) => {
            const port = basePorts[index % basePorts.length];
            const proxyAgent = new ProxyAgent(`http://127.0.0.1:${port}`);
            const nodeName = proxy.name || 'Unknown';
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFilePath = path.join(__dirname, 'temp', `clash-config-${safeNodeName}.yaml`);
            let clashProcess = null;
            let latency = 'N/A';
            let status = 'Failed';

            const result = {
                name: nodeName,
                server: proxy.server,
                port: proxy.port,
                type: proxy.type,
                test_target_url: testUrl,
                status: 'Failed',
                latency_ms: 'N/A'
            };

            try {
                await fs.mkdir(path.join(__dirname, 'temp'), { recursive: true });
                const clashConfigContent = generateClashConfig(proxy, port);
                await fs.writeFile(configFilePath, clashConfigContent, 'utf8');

                clashProcess = spawn(path.join(__dirname, 'tools', 'clash'), ['-f', configFilePath], {
                    stdio: ['ignore', 'pipe', 'pipe']
                });

                let clashOutput = '';
                clashProcess.stdout.on('data', data => clashOutput += data);
                clashProcess.stderr.on('data', data => clashOutput += data);

                if (!await checkClashReady(port)) {
                    throw new Error(`Clash failed to start: ${clashOutput.substring(0, 100)}`);
                }

                latency = await testLatency(testUrl, 3000, proxyAgent);
                status = typeof latency === 'number' ? 'Success' : `Failed: ${latency}`;
                result.latency_ms = latency;
                result.status = status;

            } catch (error) {
                status = `Error: ${error.message.substring(0, 50)}`;
                console.warn(`Test failed for ${nodeName}: ${error.message}`);
            } finally {
                if (clashProcess && !clashProcess.killed) {
                    await killClashProcess(clashProcess.pid, port);
                }
                try {
                    await fs.unlink(configFilePath);
                } catch {}
            }

            console.log(`Tested ${nodeName}: ${status}`);
            return result;
        });

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        results: testResults
    };

    try {
        await fs.writeFile(outputFilePath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`Results written to ${outputFilePath}`);
    } catch (error) {
        console.error(`Failed to write 521.yaml: ${error.message}`);
    }

    return finalReport;
}

if (require.main === module) {
    runNodeTests().then(() => console.log('Tests completed')).catch(error => {
        console.error(`Test run failed: ${error}`);
        process.exit(1);
    });
}
