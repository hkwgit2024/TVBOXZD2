const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool');
const { spawn } = require('child_process');
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

async function testDownloadSpeed(url, sizeBytes = 1000000, timeout = 10000, proxyAgent) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            dispatcher: proxyAgent
        });
        clearTimeout(id);

        if (!response.ok) return `Download Failed (Status: ${response.status})`;

        const reader = response.body.getReader();
        let downloadedBytes = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done || downloadedBytes >= sizeBytes) break;
            downloadedBytes += value?.length || 0;
        }

        const duration = (Date.now() - start) / 1000;
        if (duration === 0) return 'Calculation Error (Zero Duration)';
        const speedMbps = (downloadedBytes * 8 / (1024 * 1024)) / duration;
        return `${speedMbps.toFixed(2)} Mbps`;
    } catch (error) {
        if (error.name === 'AbortError') return `Download Timeout (${timeout}ms)`;
        return error.cause?.code ? `Download Network Error: ${error.cause.code}` : `Download Error: ${error.message.substring(0, 50)}`;
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

    const proxyName = (proxy.name || `proxy-${Math.random().toString(36).substring(7)}`).replace(/[^a-zA-Z0-9_-]/g, '_');
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
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            if (proxy.network) clashProxy.network = proxy.network;
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
            break;
        case 'trojan':
            if (!proxy.password) throw new Error('Trojan requires password');
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            if (proxy.network === 'ws' && proxy['ws-opts']) {
                clashProxy['ws-opts'] = proxy['ws-opts'];
            }
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
            if (proxy.network) clashProxy.network = proxy.network;
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
            break;
        // Optional: Restore other types if needed
        /*
        case 'ssr':
            if (!proxy.password || !proxy.cipher) throw new Error('SSR requires password and cipher');
            clashProxy.password = proxy.password;
            clashProxy.cipher = proxy.cipher;
            if (proxy.obfs) clashProxy.obfs = proxy.obfs;
            if (proxy.protocol) clashProxy.protocol = proxy.protocol;
            if (proxy.obfsparam) clashProxy.obfsParam = proxy.obfsparam;
            if (proxy.protoparam) clashProxy.protocolParam = proxy.protoparam;
            break;
        case 'hysteria':
        case 'hy':
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
        case 'hy2':
            if (!proxy.password) throw new Error('Hysteria2 requires password');
            clashProxy.password = proxy.password;
            clashProxy.tls = proxy.tls || false;
            if (proxy.servername) clashProxy.servername = proxy.servername;
            if (proxy.alpn) clashProxy.alpn = proxy.alpn;
            clashProxy.fastOpen = proxy.fastOpen || false;
            break;
        */
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
        await new Promise(resolve => exec(`lsof -ti :${port},${port + 1},${port + 2} | xargs kill -9 2>/dev/null`, resolve));
    } catch (error) {
        if (error.code !== 'ESRCH') console.warn(`Failed to kill PID ${pid}: ${error.message}`);
    }
}

async function runNodeTests() {
    const inputFilePath = path.join(__dirname, 'data', '520.yaml');
    const outputConfigPath = path.join(__dirname, 'data', '521.yaml');
    const outputReportPath = path.join(__dirname, 'data', '521_detailed_report.yaml');
    const basePorts = [7890, 7893, 7896]; // 3 concurrent ports
    const testUrl = 'http://captive.apple.com'; // Primary test endpoint
    const fallbackTestUrl = 'http://connectivitycheck.gstatic.com/generate_204'; // Fallback
    const downloadTestUrl = 'http://speedtest.tele2.net/1MB.zip'; // Optional download test

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
    const invalidDomains = [
        'russia.com', 'singapore.com', 'japan.com', 'malaysia.com',
        'icook.hk', 'icook.tw', 'time.is', 'www.gov.ua',
        'www.hugedomains.com', 'ip.sb', 'xn--b6gac.eu.org'
    ];
    const validProxies = proxiesConfig.proxies.filter(proxy => {
        if (!proxy.server || !proxy.port || !proxy.type) {
            console.warn(`Skipping proxy ${proxy.name}: missing server, port, or type`);
            return false;
        }
        if (invalidDomains.some(domain => proxy.server.includes(domain))) {
            console.warn(`Skipping proxy ${proxy.name}: invalid server domain (${proxy.server})`);
            return false;
        }
        if (!/^[a-zA-Z0-9.-]+$|^(\d{1,3}\.){3}\d{1,3}$/.test(proxy.server)) {
            console.warn(`Skipping proxy ${proxy.name}: malformed server (${proxy.server})`);
            return false;
        }
        switch (proxy.type.toLowerCase()) {
            case 'vless':
                if (!proxy.uuid) {
                    console.warn(`Skipping proxy ${proxy.name}: VLESS missing uuid`);
                    return false;
                }
                break;
            case 'trojan':
                if (!proxy.password) {
                    console.warn(`Skipping proxy ${proxy.name}: Trojan missing password`);
                    return false;
                }
                break;
            case 'ss':
                if (!proxy.cipher || !proxy.password) {
                    console.warn(`Skipping proxy ${proxy.name}: SS missing cipher or password`);
                    return false;
                }
                break;
            case 'vmess':
                if (!proxy.uuid) {
                    console.warn(`Skipping proxy ${proxy.name}: VMess missing uuid`);
                    return false;
                }
                break;
            // Optional: Add validation for other types
            /*
            case 'ssr':
                if (!proxy.password || !proxy.cipher) {
                    console.warn(`Skipping proxy ${proxy.name}: SSR missing password or cipher`);
                    return false;
                }
                break;
            case 'hysteria':
            case 'hy':
                if (!proxy.auth) {
                    console.warn(`Skipping proxy ${proxy.name}: Hysteria missing auth`);
                    return false;
                }
                break;
            case 'hysteria2':
            case 'hy2':
                if (!proxy.password) {
                    console.warn(`Skipping proxy ${proxy.name}: Hysteria2 missing password`);
                    return false;
                }
                break;
            */
        }
        return true;
    });

    console.log(`Testing ${validProxies.length} proxies with concurrency 3...`);

    const { results: testResults } = await PromisePool
        .for(validProxies)
        .withConcurrency(3)
        .process(async (proxy, index) => {
            const port = basePorts[index % basePorts.length];
            const proxyAgent = new ProxyAgent(`http://127.0.0.1:${port}`);
            const nodeName = proxy.name || 'Unknown';
            const safeNodeName = nodeName.replace(/[^a-zA-Z0-9_-]/g, '_');
            const configFilePath = path.join(__dirname, 'temp', `clash-config-${safeNodeName}.yaml`);
            let clashProcess = null;
            let latency = 'N/A';
            let downloadSpeed = 'Not Tested';
            let status = 'Failed';

            const result = {
                name: nodeName,
                server: proxy.server,
                port: proxy.port,
                type: proxy.type,
                test_target_url: testUrl,
                status: 'Failed',
                latency_ms: 'N/A',
                download_speed: 'Not Tested'
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
                if (typeof latency !== 'number') {
                    latency = await testLatency(fallbackTestUrl, 3000, proxyAgent); // Try fallback URL
                }

                if (typeof latency === 'number') {
                    status = 'Success';
                    // Optional: Test download speed if latency test succeeds
                    downloadSpeed = await testDownloadSpeed(downloadTestUrl, 1000000, 10000, proxyAgent);
                } else {
                    status = `Failed: ${latency}`;
                }

                result.latency_ms = latency;
                result.status = status;
                result.download_speed = downloadSpeed;

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

    // Generate importable config
    const successfulProxies = testResults.filter(result => result.status === 'Success');
    const importableConfig = {
        port: 7890,
        'socks-port': 7891,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'error',
        'external-controller': '127.0.0.1:9090',
        proxies: successfulProxies.map(result => {
            const originalProxy = proxiesConfig.proxies.find(p => p.name === result.name);
            return originalProxy || null;
        }).filter(p => p !== null),
        'proxy-groups': [
            { name: 'Proxy', type: 'select', proxies: successfulProxies.map(p => p.name) },
            { name: 'Fallback', type: 'fallback', proxies: successfulProxies.map(p => p.name), url: testUrl, interval: 300 },
            { name: 'Auto', type: 'url-test', proxies: successfulProxies.map(p => p.name), url: testUrl, interval: 300 }
        ],
        rules: [
            'DOMAIN-SUFFIX,google.com,Proxy',
            'DOMAIN-SUFFIX,youtube.com,Proxy',
            'DOMAIN-SUFFIX,netflix.com,Proxy',
            'DOMAIN-SUFFIX,facebook.com,Proxy',
            'DOMAIN-SUFFIX,twitter.com,Proxy',
            'DOMAIN-SUFFIX,wikipedia.org,Proxy',
            'GEOIP,CN,DIRECT',
            'MATCH,Proxy'
        ]
    };

    // Write output files
    try {
        await fs.writeFile(outputConfigPath, yaml.dump(importableConfig, { lineWidth: -1 }), 'utf8');
        console.log(`Importable config written to ${outputConfigPath}`);
    } catch (error) {
        console.error(`Failed to write ${outputConfigPath}: ${error.message}`);
    }

    const finalReport = {
        timestamp: new Date().toISOString(),
        tested_proxies_count: testResults.length,
        successful_proxies_count: successfulProxies.length,
        results: testResults
    };

    try {
        await fs.writeFile(outputReportPath, yaml.dump(finalReport, { lineWidth: -1 }), 'utf8');
        console.log(`Detailed report written to ${outputReportPath}`);
    } catch (error) {
        console.error(`Failed to write ${outputReportPath}: ${error.message}`);
    }

    return finalReport;
}

if (require.main === module) {
    runNodeTests().then(() => console.log('Tests completed')).catch(error => {
        console.error(`Test run failed: ${error}`);
        process.exit(1);
    });
}
