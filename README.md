# 查看帮助

关键参数解读

-c <文件路径或URL>: 这是最重要的参数，用来指定你的 Clash 配置文件或订阅链接。你可以传入本地文件的路径，也可以直接传入一个 HTTP(S) 订阅地址。

-f <正则表达式>: 使用正则表达式来过滤节点。比如，-f 'HK|港' 会只测试节点名称中包含“HK”或“港”的节点。

-output <文件路径>: 指定输出文件的路径。测速和筛选完成后，工具会生成一个只包含合格节点的新配置文件。

-rename: 这个参数会自动根据节点的 IP 地理位置和测速结果来重命名节点。

-fast: 启用快速模式。此模式下，工具只测试节点延迟，跳过带宽测试，这对于快速检查节点是否可用非常有用。

性能筛选参数
这些参数可以帮助你筛选出符合特定性能要求的节点：

-max-latency <时间>: 过滤掉延迟超过该值的节点。例如，-max-latency 800ms 会排除延迟高于 800 毫秒的节点。

-min-download-speed <速度>: 过滤掉下载速度低于该值的节点。这里的速度单位是 MB/s。例如，-min-download-speed 5 会排除下载速度低于 5 MB/s 的节点。

-min-upload-speed <速度>: 过滤掉上传速度低于该值的节点。这里的速度单位也是 MB/s。

测速原理
clash-speedtest 的测速基于两个核心指标：

带宽：指下载指定文件（默认 50MB）的速度，反映节点的出口带宽。

延迟：指请求发出到收到第一个字节的响应时间（TTFB），反映你到节点的连接速度。

文档特别强调，带宽和延迟是两个独立的指标，高带宽不等于低延迟，反之亦然。



> clash-speedtest -h
Usage of clash-speedtest:
  -c string
        configuration file path, also support http(s) url
  -f string
        filter proxies by name, use regexp (default ".*")
  -b string
        block proxies by keywords, use | to separate multiple keywords (example: -b 'rate|x1|1x')
  -server-url string
        server url for testing proxies (default "https://speed.cloudflare.com")
  -download-size int
        download size for testing proxies (default 50MB)
  -upload-size int
        upload size for testing proxies (default 20MB)
  -timeout duration
        timeout for testing proxies (default 5s)
  -concurrent int
        download concurrent size (default 4)
  -output string
        output config file path (default "")
  -stash-compatible
        enable stash compatible mode
  -max-latency duration
        filter latency greater than this value (default 800ms)
  -min-download-speed float
        filter speed less than this value(unit: MB/s) (default 5)
  -min-upload-speed float
        filter upload speed less than this value(unit: MB/s) (default 2)
  -rename
        rename nodes with IP location and speed
  -fast
        enable fast mode, only test latency

# 演示：

# 1. 测试全部节点，使用 HTTP 订阅地址
# 请在订阅地址后面带上 flag=meta 参数，否则无法识别出节点类型
> clash-speedtest -c 'https://domain.com/api/v1/client/subscribe?token=secret&flag=meta'

# 2. 测试香港节点，使用正则表达式过滤，使用本地文件
> clash-speedtest -c ~/.config/clash/config.yaml -f 'HK|港'
节点                                        	带宽          	延迟
Premium|广港|IEPL|01                        	484.80KB/s  	815.00ms
Premium|广港|IEPL|02                        	N/A         	N/A
Premium|广港|IEPL|03                        	2.62MB/s    	333.00ms
Premium|广港|IEPL|04                        	1.46MB/s    	272.00ms
Premium|广港|IEPL|05                        	3.87MB/s    	249.00ms

# 3. 当然你也可以混合使用
> clash-speedtest -c "https://domain.com/api/v1/client/subscribe?token=secret&flag=meta,/home/.config/clash/config.yaml"

# 4. 筛选出延迟低于 800ms 且下载速度大于 5MB/s 的节点，并输出到 filtered.yaml
> clash-speedtest -c "https://domain.com/api/v1/client/subscribe?token=secret&flag=meta" -output filtered.yaml -max-latency 800ms -min-speed 5
# 筛选后的配置文件可以直接粘贴到 Clash/Mihomo 中使用，或是贴到 Github\Gist 上通过 Proxy Provider 引用。

# 5. 使用 -rename 选项按照 IP 地区和下载速度重命名节点
> clash-speedtest -c config.yaml -output result.yaml -rename
# 重命名后的节点名称格式：🇺🇸 US | ⬇️ 15.67 MB/s
# 包含国旗 emoji、国家代码和下载速度

# 6. 快速测试模式
> clash-speedtest -f 'HK' -fast -c ~/.config/clash/config.yaml
# 此命令将只测试节点延迟，跳过其他测试项目，适用于：
# - 快速检查节点是否可用
# - 只需要检查延迟的场景
# - 需要快速得到测试结果的场景
🇭🇰 香港 HK-10 100% |██████████████████| (20/20, 13 it/min)
序号    节点名称                类型            延迟
1.      🇭🇰 香港 HK-01           Trojan          657ms
2.      🇭🇰 香港 HK-20           Trojan          649ms
3.      🇭🇰 香港 HK-15           Trojan          674ms
4.      🇭🇰 香港 HK-19           Trojan          649ms
5.      🇭🇰 香港 HK-12           Trojan          667ms


测速文件列表
ASH 测速文件
http://ash.icmp.hetzner.com/100MB.bin
http://ash.icmp.hetzner.com/1GB.bin
http://ash.icmp.hetzner.com/10GB.bin
http://ash.icmp.hetzner.com/
HEL1 测速文件
http://hel.icmp.hetzner.com/100MB.bin
http://hel.icmp.hetzner.com/1GB.bin
http://hel.icmp.hetzner.com/10GB.bin
http://hel.icmp.hetzner.com/
FSN1 测速文件
http://fsn.icmp.hetzner.com/100MB.bin
http://fsn.icmp.hetzner.com/1GB.bin
http://fsn.icmp.hetzner.com/10GB.bin
http://fsn.icmp.hetzner.com/
NBG1 测速文件
https://speed.hetzner.de/100MB.bin
https://speed.hetzner.de/1GB.bin
https://speed.hetzner.de/10GB.bin
https://speed.hetzner.de/

100MB：https://speed.cloudflare.com/__down?bytes=104857600
200MB：https://speed.cloudflare.com/__down?bytes=209715200

-download-size 参数只接受整数作为输入，单位是字节（bytes）。50MB 这样的字符串格式是无效的。

从 clash-speedtest 的帮助信息中可以看到，-download-size 的默认值是 52428800，这正好是 50MB 的字节数。

-server-url "https://mmatechnical.com/Download/Download-Test-File/(MMA)-100MB.zip" \
-download-size 52428800 \
https://1100mb.com/files
https://mmatechnical.com/download-test-files/
