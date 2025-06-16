const fs = require('fs/promises');
const yaml = require('js-yaml');
const path = require('path');
const { PromisePool } = require('@supercharge/promise-pool');
const { spawn } = require('child_process');
const { setTimeout, clearTimeout } = require('timers');
const { ProxyAgent } = require('undici');

let globalProxyAgent;

async function testLatency(url, timeout = 5000) {
    const start = Date.now();
    try {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
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

function generateClashConfig(proxy, port = 7890) {
    const config = {
        port: port,
        'socks-port': port + 1,
        'allow-lan': false,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': `127.0.0.1:${port + 2}`,
        proxies: [],
        'proxy-groups': [],
        rules: []
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
            if (proxy.servername) clashProxy.servername = proxy.server
