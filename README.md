https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/clash.yaml
https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/output/iptv_list.txt

### 来源项目

本项目的核心功能和灵感来自以下开源项目，在此向各位作者表示诚挚的感谢：

* **[skywrt](https://github.com/skywrt)**
* **[chengaopan/AutoMergePublicNodes](https://github.com/chengaopan/AutoMergePublicNodes)**
* **[peasoft/NoMoreWalls](https://github.com/peasoft/NoMoreWalls)**
* **[fish2018/ClashForge](https://github.com/fish2018/ClashForge)**
* **[faceair/clash-speedtest](https://github.com/faceair/clash-speedtest)**
* **[awuaaaaa/vless-py](https://github.com/awuaaaaa/vless-py)**
* **[wzdnzd/aggregator](https://github.com/wzdnzd/aggregator)**
* **[0xJins/x.sub](https://github.com/0xJins/x.sub)**
* **[w1770946466/Auto_proxy](https://github.com/w1770946466/Auto_proxy)**
* **[VPNforWindowsSub/base64](https://github.com/VPNforWindowsSub/base64)**
* **[mojolabs-id/GeoLite2-Database](https://github.com/mojolabs-id/GeoLite2-Database)**
* **[midpoint/ClashForge](https://github.com/midpoint/ClashForge)**
* **[mlzlzj/df](https://github.com/mlzlzj/df)**
* **[YamaXanadu830/clash-speedtest](https://github.com/YamaXanadu830/clash-speedtest)]**
  -----

## faceair 节点测速工具（clash-speedtest）

### 关键参数解读

#### 基础用法

  * `-c <文件路径或URL>`：**最重要的参数**，用于指定你的 Clash 配置文件或订阅链接。支持本地文件路径或 HTTP(S) URL。
  * `-f <正则表达式>`：使用正则表达式来**过滤节点**。例如，`-f 'HK|港'` 会只测试节点名称中包含“HK”或“港”的节点。
  * `-b <关键字>`：使用 `|` 分隔的关键字来**屏蔽节点**。例如，`-b 'rate|x1|1x'` 会屏蔽包含这些关键字的节点。
  * `-output <文件路径>`：指定测速和筛选结果的输出文件路径。
  * `-rename`：自动根据节点的 IP 地理位置和测速结果来**重命名节点**。
  * `-fast`：启用快速模式，**只测试节点延迟**，跳过带宽测试。

#### 性能筛选

  * `-max-latency <时间>`：过滤掉延迟超过该值的节点。单位为 `ms`。例如，`-max-latency 800ms`。
  * `-min-download-speed <速度>`：过滤掉下载速度低于该值的节点。这里的速度单位是 **MB/s**。例如，`-min-download-speed 5`。
  * `-min-upload-speed <速度>`：过滤掉上传速度低于该值的节点。这里的速度单位也是 **MB/s**。

-----

## 命令行演示

```bash
# 1. 测试全部节点，使用 HTTP 订阅地址
# 请在订阅地址后面带上 flag=meta 参数，否则无法识别出节点类型
clash-speedtest -c 'https://domain.com/api/v1/client/subscribe?token=secret&flag=meta'

# 2. 测试香港节点，使用本地文件
clash-speedtest -c ~/.config/clash/config.yaml -f 'HK|港'

# 3. 筛选出延迟低于 800ms 且下载速度大于 5MB/s 的节点，并输出到 filtered.yaml
clash-speedtest -c 'https://domain.com/api/v1/client/subscribe?token=secret&flag=meta' -output filtered.yaml -max-latency 800ms -min-download-speed 5

# 4. 使用 -rename 选项按照 IP 地区和下载速度重命名节点
clash-speedtest -c config.yaml -output result.yaml -rename
```

-----

## 测速文件列表

你可以通过 `-server-url` 参数指定以下任何测速文件进行测试。

### Cloudflare

  * 100MB：`https://speed.cloudflare.com/__down?bytes=104857600`
  * 200MB：`https://speed.cloudflare.com/__down?bytes=209715200`

> **注意**：`-download-size` 参数只接受整数（字节）作为输入。`50MB` 等字符串格式是无效的。例如，50MB 对应的字节数为 `52428800`。

### Hetzner

  * **ASH 测速文件**
      * `http://ash.icmp.hetzner.com/100MB.bin`
      * `http://ash.icmp.hetzner.com/1GB.bin`
  * **HEL1 测速文件**
      * `http://hel.icmp.hetzner.com/100MB.bin`
      * `http://hel.icmp.hetzner.com/1GB.bin`
  * **FSN1 测速文件**
      * `http://fsn.icmp.hetzner.com/100MB.bin`
      * `http://fsn.icmp.hetzner.com/1GB.bin`
  * **NBG1 测速文件**
      * `https://speed.hetzner.de/100MB.bin`
      * `https://speed.hetzner.de/1GB.bin`

### 其他测速文件

  * `https://mmatechnical.com/Download/Download-Test-File/(MMA)-100MB.zip`
  * `https://1100mb.com/files`
  * `https://mmatechnical.com/download-test-files/`
