#!/bin/bash

# 定义日志文件和输出文件的路径
LOG_FILE="node_connectivity_results.log"
OUTPUT_DIR="data"
SUCCESS_FILE="$OUTPUT_DIR/sub.txt"        # 成功节点输出文件
FAILED_FILE="$OUTPUT_DIR/failed_nodes.log" # 失败节点输出文件
MERGED_NODES_TEMP_FILE=$(mktemp) # 使用 mktemp 创建唯一的临时文件，用于合并所有来源的原始节点列表
ALL_TEST_RESULTS_TEMP_FILE=$(mktemp) # 新增：用于收集所有并行测试结果的临时文件

# 定义所有节点来源URL的数组
NODE_SOURCES=(
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    #"https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt"
    #"https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    #"https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    "https://chromego-sub.netlify.app/sub/merged_proxies_new.yaml"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0s0JGGsOUvbxgjaKHkYqnj4jU0SsWUMb3aYMcFW?oQqqQ"
"https://shadowmere.akiel.dev/api/b64sub/"
"https://sezar.hossein.om.to"
"https://unlimited.spauu.web.id"
"https://cache.netflix.com.unlimited.spauu.web.id"
"http://unlimited.spauu.web.id"
"https://vip.arivganteng.biz.id"
"https://bayoeorescentpossessicoanseparateuneforescenphocommitte.adoptangelaboradvacotionclwonthorughconfrmcompimentdeseertaltar.org/link/wUb3aAiSamxS64nu?clash=2"
"https://jiang.netlify.app/"
"https://gitlab.com/univstar1/v2ray/-/raw/main/data/v2ray/general.txt"
"https://jsd.cdn.zzko.cn/gh/anaer/Sub@main/clash.yaml"
"https://submit.xz61.cn:23443/api/v1/client/subscribe?token=29e76b78176d9c53a85333df23b38c49"
"https://0b96e976-9ec3-44c0-aa2b-30bf8b0792ea.com/api/v1/client/subscribe?token=7e22d54bf813350a216f444453a7dbb4"
"https://pqjc.site/api/v1/client/subscribe?token=b92ab3eb3b0b0a0aef32bde6dbbc8b52"
"https://pqjc.site/api/v1/client/subscribe?token=823c3efb64db734f78bf7d0971669efe"
"https://xn--cp3a08l.com/api/v1/client/subscribe?token=cfef906df0fcc536603d9d04696a3dfb&flag=meta"
"http://investor.fb.com.freexxx.ndeso.web.id"
"https://freevpn.cloudproxyip.my.id"
"https://cache.netflix.com.freexxx.turah.my.id"
"https://blog.webex.com.web.bmkg.xyz"
"https://freevpn.ndeso.web.id"
"https://investors.spotify.com.freevpn.xhamster.biz.id"
"http://zaintest.vuclip.com.freevpn.ndeso.web.id"
"https://ads.ruangguru.com.freexxx.xhamster.biz.id"
"https://cache.netflix.com.freexxx.xhamster.biz.id"
"https://io.ruangguru.com.freexxx.ndeso.xyz"
"http://cache.netflix.com.freevpn.xhamster.biz.id"
"http://quiz.int.vidio.com.freevpn.najah.biz.id"
"https://io.ruangguru.com.freevpn.bmkg.xyz"
"https://io.ruangguru.com.freexxx.turah.my.id"
"https://investor.fb.com.freexxx.cloudproxyip.my.id"
"http://ads.ruangguru.com.freevpn.ndeso.xyz"
"http://cache.netflix.com.freevpn.najah.biz.id"
"https://investors.spotify.com.freexxx.ndeso.xyz"
"https://investors.spotify.com.freevpn.bmkg.xyz"
"https://blog.webex.com.freexxx.bmkg.xyz"
"https://investors.spotify.com.web.bmkg.xyz"
"http://support.zoom.us.freevpn.ndeso.xyz"
"https://quiz.int.vidio.com.freexxx.ndeso.xyz"
"https://freexxx.turah.my.id"
"https://freexxx.ndeso.xyz"
"https://investor.fb.com.freevpn.turah.my.id"
"http://ads.ruangguru.com.freexxx.najah.biz.id"
"http://io.ruangguru.com.freevpn.ndeso.web.id"
"http://ava.game.naver.com.freevpn.najah.biz.id"
"https://api.midtrans.com.web.bmkg.xyz"
"http://freevpn.bmkg.xyz"
"https://investor.fb.com.freevpn.xhamster.biz.id"
"https://api.midtrans.com.freevpn.ndeso.web.id"
"https://investor.fb.com.freexxx.ndeso.xyz"
"https://freexxx.xhamster.biz.id"
"http://quiz.int.vidio.com.web.bmkg.xyz"
"http://quiz.int.vidio.com.freevpn.xhamster.biz.id"
"https://ads.ruangguru.com.freexxx.turah.my.id"
"http://investors.spotify.com.aink.workerz.site"
"http://api.midtrans.com.freevpn.cloudproxyip.my.id"
"https://live.iflix.com.freevpn.xhamster.biz.id"
"http://live.iflix.com.freevpn.xhamster.biz.id"
"https://ava.game.naver.com.freevpn.xhamster.biz.id"
"https://freexxx.ndeso.web.id"
"http://investors.spotify.com.freexxx.turah.my.id"
"https://freexxx.cloudproxyip.my.id"
"http://investor.fb.com.freexxx.ndeso.xyz"
"http://freexxx.xhamster.biz.id"
"http://api.midtrans.com.freexxx.turah.my.id"
"https://support.zoom.us.freexxx.xhamster.biz.id"
"https://live.iflix.com.freevpn.turah.my.id"
"http://io.ruangguru.com.freevpn.turah.my.id"
"http://investors.spotify.com.freevpn.xhamster.biz.id"
"http://io.ruangguru.com.freexxx.bmkg.xyz"
"http://live.iflix.com.freevpn.turah.my.id"
"https://freexxx.bmkg.xyz"
"http://zaintest.vuclip.com.freevpn.bmkg.xyz"
"https://support.zoom.us.freevpn.xhamster.biz.id"
"https://zaintest.vuclip.com.freevpn.bmkg.xyz"
"http://ads.ruangguru.com.freexxx.xhamster.biz.id"
"https://ads.ruangguru.com.freevpn.ndeso.xyz"
"http://investors.spotify.com.freevpn.najah.biz.id"
"http://freevpn.ndeso.web.id"
"http://investors.spotify.com.web.bmkg.xyz"
"http://quiz.int.vidio.com.freevpn.bmkg.xyz"
"https://investors.spotify.com.freevpn.ndeso.xyz"
"https://cache.netflix.com.freevpn.cloudproxyip.my.id"
"http://cache.netflix.com.freevpn.turah.my.id"
"http://freevpn.turah.my.id"
"http://cache.netflix.com.freexxx.turah.my.id"
"https://quiz.int.vidio.com.web.bmkg.xyz"
"http://support.zoom.us.web.bmkg.xyz"
"http://freexxx.ndeso.xyz"
"https://api.midtrans.com.freexxx.ndeso.web.id"
"http://freexxx.cloudproxyip.my.id"
"http://ava.game.naver.com.web.bmkg.xyz"
"https://freevpn.turah.my.id"
"https://zaintest.vuclip.com.freevpn.xhamster.biz.id"
"https://investor.fb.com.freexxx.xhamster.biz.id"
"http://api.midtrans.com.web.bmkg.xyz"
"http://blog.webex.com.freevpn.najah.biz.id"
"http://live.iflix.com.freevpn.ndeso.web.id"
"http://freexxx.turah.my.id"
"http://quiz.int.vidio.com.freexxx.turah.my.id"
"http://investors.spotify.com.freevpn.bmkg.xyz"
"http://live.iflix.com.freevpn.cloudproxyip.my.id"
"https://ads.ruangguru.com.freevpn.xhamster.biz.id"
"https://investor.fb.com.freevpn.najah.biz.id"
"http://live.iflix.com.web.bmkg.xyz"
"https://live.iflix.com.freevpn.bmkg.xyz"
"https://ads.ruangguru.com.web.bmkg.xyz"
"http://blog.webex.com.web.bmkg.xyz"
"https://zaintest.vuclip.com.freevpn.ndeso.xyz"
"https://web.bmkg.xyz"
"http://support.zoom.us.freexxx.turah.my.id"
"https://api.midtrans.com.freexxx.ndeso.xyz"
"http://investors.spotify.com.freevpn.ndeso.web.id"
"http://ads.ruangguru.com.freexxx.ndeso.xyz"
"https://ads.ruangguru.com.freevpn.turah.my.id"
"https://support.zoom.us.freevpn.ndeso.xyz"
"http://quiz.int.vidio.com.freexxx.ndeso.xyz"
"https://support.zoom.us.freexxx.turah.my.id"
"http://blog.webex.com.freexxx.bmkg.xyz"
"https://live.iflix.com.freevpn.ndeso.web.id"
"https://ava.game.naver.com.freevpn.ndeso.xyz"
"https://quiz.int.vidio.com.freevpn.bmkg.xyz"
"http://ava.game.naver.com.freevpn.ndeso.xyz"
"http://ads.ruangguru.com.freevpn.turah.my.id"
"https://io.ruangguru.com.freexxx.najah.biz.id"
"http://support.zoom.us.freexxx.xhamster.biz.id"
"http://ads.ruangguru.com.web.bmkg.xyz"
"https://cache.netflix.com.freevpn.najah.biz.id"
"http://live.iflix.com.freevpn.bmkg.xyz"
"https://live.iflix.com.freevpn.cloudproxyip.my.id"
"https://investors.spotify.com.freevpn.najah.biz.id"
"http://investors.spotify.com.freexxx.ndeso.xyz"
"https://quiz.int.vidio.com.freexxx.turah.my.id"
"https://api.midtrans.com.freevpn.cloudproxyip.my.id"
"http://io.ruangguru.com.freexxx.najah.biz.id"
"http://freevpn.cloudproxyip.my.id"
"https://ava.game.naver.com.freevpn.ndeso.web.id"
"https://investor.fb.com.freexxx.ndeso.web.id"
"http://freexxx.najah.biz.id"
"http://api.midtrans.com.freexxx.ndeso.xyz"
"https://ads.ruangguru.com.freexxx.ndeso.xyz"
"http://freexxx.bmkg.xyz"
"http://api.midtrans.com.freexxx.bmkg.xyz"
"http://api.midtrans.com.freexxx.ndeso.web.id"
"http://investor.fb.com.freevpn.najah.biz.id"
"http://zaintest.vuclip.com.freevpn.najah.biz.id"
"https://cache.netflix.com.freevpn.xhamster.biz.id"
"http://api.midtrans.com.freevpn.ndeso.web.id"
"https://api.midtrans.com.freexxx.bmkg.xyz"
"http://ads.ruangguru.com.freevpn.xhamster.biz.id"
"http://investor.fb.com.freevpn.xhamster.biz.id"
"http://live.iflix.com.freexxx.xhamster.biz.id"
"https://api.midtrans.com.freexxx.xhamster.biz.id"
"https://cache.netflix.com.freevpn.turah.my.id"
"https://investors.spotify.com.freexxx.turah.my.id"
"http://zaintest.vuclip.com.freevpn.xhamster.biz.id"
"https://freevpn.ndeso.xyz"
"https://investors.spotify.com.freevpn.turah.my.id"
"http://io.ruangguru.com.freexxx.ndeso.xyz"
"https://quiz.int.vidio.com.freevpn.najah.biz.id"
"https://freevpn.bmkg.xyz"
"https://ads.ruangguru.com.freexxx.najah.biz.id"
"https://support.zoom.us.web.bmkg.xyz"
"https://quiz.int.vidio.com.freevpn.xhamster.biz.id"
"https://freexxx.najah.biz.id"
"http://cache.netflix.com.freexxx.cloudproxyip.my.id"
"https://ava.game.naver.com.web.bmkg.xyz"
"https://api.midtrans.com.freevpn.ndeso.xyz"
"https://live.iflix.com.freexxx.xhamster.biz.id"
"http://investors.spotify.com.freevpn.ndeso.xyz"
"http://blog.webex.com.freexxx.ndeso.web.id"
"https://blog.webex.com.freevpn.ndeso.web.id"
"http://cache.netflix.com.freevpn.cloudproxyip.my.id"
"http://investor.fb.com.freevpn.turah.my.id"
"https://investors.spotify.com.freevpn.ndeso.web.id"
"https://live.iflix.com.freexxx.ndeso.xyz"
"http://web.bmkg.xyz"
"http://ads.ruangguru.com.freevpn.cloudproxyip.my.id"
"http://ads.ruangguru.com.freexxx.turah.my.id"
"https://cache.netflix.com.freexxx.cloudproxyip.my.id"
"http://api.midtrans.com.freevpn.ndeso.xyz"
"https://ava.game.naver.com.freevpn.najah.biz.id"
"http://cache.netflix.com.freexxx.xhamster.biz.id"
"http://investors.spotify.com.freevpn.turah.my.id"
"http://io.ruangguru.com.freevpn.bmkg.xyz"
"http://freevpn.xhamster.biz.id"
"https://live.iflix.com.web.bmkg.xyz"
"http://investor.fb.com.freexxx.cloudproxyip.my.id"
"http://live.iflix.com.freexxx.ndeso.xyz"
"https://blog.webex.com.freexxx.cloudproxyip.my.id"
"http://investor.fb.com.freexxx.xhamster.biz.id"
"https://ads.ruangguru.com.freevpn.cloudproxyip.my.id"
"https://investors.spotify.com.aink.workerz.site"
"https://blog.webex.com.freevpn.najah.biz.id"
"https://freevpn.xhamster.biz.id"
"https://zaintest.vuclip.com.freevpn.najah.biz.id"
"https://io.ruangguru.com.freevpn.ndeso.web.id"
"http://freexxx.ndeso.web.id"
"http://ava.game.naver.com.freevpn.ndeso.web.id"
"http://cache.netflix.com.web.bmkg.xyz"
"https://cache.netflix.com.web.bmkg.xyz"
"https://io.ruangguru.com.freexxx.bmkg.xyz"
"http://ava.game.naver.com.freevpn.xhamster.biz.id"
"https://api.midtrans.com.freexxx.turah.my.id"
"http://blog.webex.com.freexxx.cloudproxyip.my.id"
"http://io.ruangguru.com.freexxx.turah.my.id"
"https://zaintest.vuclip.com.freevpn.ndeso.web.id"
"https://blog.webex.com.freexxx.ndeso.web.id"
"http://support.zoom.us.freevpn.xhamster.biz.id"
"http://freevpn.ndeso.xyz"
"http://zaintest.vuclip.com.freevpn.ndeso.xyz"
"https://io.ruangguru.com.freevpn.turah.my.id"
"https://s1.bnpublicsub.net/api/v1/client/subscribe?token=43bf581fc4f899a39313626a18190a48"
"https://link02.qytsub02.pro/api/v1/client/subscribe?token=98966ee683b1723b461b61c5f47b09f7"
"https://subapi01.qytsublink.com/api/v1/client/subscribe?token=98966ee683b1723b461b61c5f47b09f7"
"https://sublink.52cloud.eu.org/api/v1/client/subscribe?token=8025d164-d726-40ed-af06-d7ea1138d1a4"
"https://mioch.online"
"https://vless-cf.mioch.online"
"https://zoomgov.com.vless-cf.mioch.online"
"http://vless-cf.mioch.online"
"http://zoomgov.com.vless-cf.mioch.online"
"https://api1.fzdwf.top/api/v1/client/subscribe?token=67706c7a66b91ab14742f3e54771037f"
"https://fstores.web.id"
"https://a.fstores.web.id"
"http://fstores.web.id"
"https://b.fstores.web.id"
"http://a.fstores.web.id"
"http://b.fstores.web.id"
"https://rgergergergerg6555.saojc.xyz/api/v1/client/subscribe?token=750810736ea0883ffd61f1b1c416b885"
"https://rgergergergerg6555.saojc.xyz/api/v1/client/subscribe?token=8bfe44de3e472e85895e8a57e265b7f0"
"https://goo.su/UBgqxhF"
"https://www.flyintpro05.com/api/v1/client/subscribe?token=62be89e4bc828cdfd0c62bfb44746312"
"https://link01.fliggylink.xyz/api/v1/client/subscribe?token=fe86cc67f7404c08e5f9d70343329667"
"https://unicorncloud.club/api/v1/client/subscribe?token=ad495fe15a7197e7fac7913e8a239dc6"
"https://my5353.com/zuihuacloud"
"https://feiniaoyun.top/api/v1/client/subscribe?token=fa2021e5a0e54c18b168790ad3c96a1c"
"https://fn1.595780.xyz/api/v1/client/subscribe?token=283ba0a08745237e6e1507150261fbac"
"https://mojie.best/api/v1/client/subscribe?token=fff446368097db5b2708d69fc7f998e6"
"https://onlysub.mjurl.com/api/v1/client/subscribe?token=24691c7db62c4214d6e96ff128da0b6f"
"https://msub.fengchiyx.xyz/api/v1/client/subscribe?token=34ff9012ec68f9c521fc559a83146eba"
"https://fn1.170809.xyz/api/v1/client/subscribe?token=d0e40e7ce88e354269b14e2c999820c2"
"https://onlysub.mjurl.com/api/v1/client/subscribe?token=6dbf0b92279e3ca9448b883496d8870f"
"https://mojie.co/api/v1/client/subscribe?token=21e29de55733e92dbb0b0af9f048b294"
"https://mojie.online/api/v1/client/subscribe?token=377290cae8c64bec51d331e646ed4444"
"https://mojie.best/api/v1/client/subscribe?token=7b6ed1c61010e0e4098bf598f9deab9b"
"https://shadowshare.v2cross.com/publicserver/servers/temp/FJc9C05qfPbvSLwK"
"https://2381bfde-8c93-4701-8f14-24f071067a1a.nginx24bit.xyz/api/v1/client/subscribe?token=7a34a7e4d092c4bc11064c4ca594a15c"
"https://xxbodejxc.netlify.app/"
"https://sub.cokecloud.world/api/v1/client/subscribe?token=7f3929bf59f27b8a72a56f79c2696489"
"https://cola.xn--chqu2nzsxv3y.com/api/v1/client/subscribe?token=84addb61c3a2639f5a2fa219771e6e9d"
"https://cola.xn--chqu2nzsxv3y.com/api/v1/client/subscribe?token=dc651326e2ce650def8fc3772d7187c5"
"https://s1.bnsubservdom.com/api/v1/client/subscribe?token=c03752033d7f2b0ba9f1e8ef0b174307"
"https://sub-9pu.pages.dev/sub"
"https://sakuracat1203.xn--3iq226gfdb94q.com/api/v1/client/subscribe?token=1356f5110c60f1e8823a0962af290c72"
"https://jsjc.cfd/api/v1/client/subscribe?token=ccf3923d2eafebf794a51cbd1c8dd2ae"
"https://microsoft-update-daily.com/api/v1/client/subscribe?token=d0d537001a9c1a37f601c08a4b1c7441"
"https://52daishu.uk/api/v1/client/subscribe?token=7ac825032570a917a24257a04a68568a"
"https://ednovas.tech/api/v1/client/subscribe?token=d166f40c0cd9e64876c013b0d34f7054"
"https://ednovas.world/api/v1/client/subscribe?token=9469a08d8cd4521c3c71471331b48254"
"https://sub.bxy.org.uk/api/v1/client/subscribe?token=e57e0cae5405ee66d3eb9059a4e7e13a&"
"https://s.33y.run/v3/subscr?id=59aefa2d968a472bbbe0905bb3ae492e"
"https://knjc.cfd/api/v1/client/subscribe?token=6b9d5809807e0eab943682f6a80fdc17&amp;flag=meta"
"https://s.33y.run/v3/subscr?id=0ba4a24015864a54929c26389c8a4111"
"https://raw.gitmirror.com/ripaojiedian/freenode/main/sub"
"https://088ea81a-3547-85e0-4af6-dfcb3c6674aa.372372.xyz/api/v1/client/subscribe?token=5cb24ce689fecdb776dbcc0f5c29fde5"
"https://raw.gitmirror.com/ripaojiedian/freenode/main/clash"
"https://b3b0549e-160e-495a-a528-cccf5148bc48.372372.xyz/api/v1/client/subscribe?token=db8f691dbae4050ab22e5fe68351befb&amp;flag=clash"
"https://fs.v2rayse.com/share/20240710/fwbru0nwep.yaml"
"https://sub.xiaomf.store/link/LLWmOb0Dz6klyVIi?clash=1"
"https://www.xmfvpn.com/link/2WpHCW9F5AvnvSu4?list=shadowrocket"
"https://speedx2net.postshup.ir:2096/sub/S3VyZFZwbl8zMEdiLDE3NDE0MDkyNzcO4PFMVZoWk"
"https://freenode.openrunner.net/uploads/20240425-clash.yaml"
"https://api.liltjay.ip-ddns.com/TQWMYCWH2D"
"http://sub.966888.xyz/api/v1/client/subscribe?token=7b77ede392015975e9af44bd33ac3b2c"
"https://sub.966888.xyz/api/v1/client/subscribe?token=3396f01edae0b7e0c619aea607cbba3a&amp;flag=clash"
"https://sub.czrk168.top/api/v1/client/subscribe?token=135c202776a837a637ec1e03fe0d8102"
"https://sub.966888.xyz/api/v1/client/subscribe?token=3396f01edae0b7e0c619aea607cbba3a&amp;amp;flag=clash"
"http://sub.966888.xyz/api/v1/client/subscribe?token=2d9f235fd8bfb44861f16fb14aed4b0d"
"https://sub.966888.xyz/api/v1/client/subscribe?token=3396f01edae0b7e0c619aea607cbba3a"
"https://subscribe.wogame.org/api/v1/client/subscribe?token=6bd6e5193a4034bfd6e8d201d98cb065"
"https://getafreenode.com/subscribe/?uuid=2F094845-E2BD-EBF7-DEB7-995992436FAF"
"https://getafreenode.com/subscribe/?uuid=8376D053-54C6-837B-0627-7A894346F523"
"https://getafreenode.com/subscribe/?uuid=143D3944-0874-CCE5-5668-41A848088DAA"
"https://subscription.und32w4732.top/b0e6b701-ac88-4f24-9c3c-3984fd44c7ab/ss"
"https://subscription.und32w4732.top/bce03a2d-52ce-498a-a7f9-377a4bf427dc/ss"
"https://subscription.und32w4732.top/0175b51b-83e1-4143-80ea-b0afff8868d4/ss"
"https://subscription.und32w4732.top/e376e48d-a76b-453f-941c-b1aac22bf78c/ss"
"https://subscription.und32w4732.top/bb0f984b-446d-4992-a344-c6e80e736440/ss"
"https://subscription.und32w4732.top/af637408-632f-46ce-9d1c-f85d353e4318/ss"
"https://subscription.und32w4732.top/5dd46747-ef99-418c-b37c-0a9b3314faf4/ss"
"https://git.io/emzclash"
"https://subscription.und32w4732.top/d3c93b2c-18a9-4da1-bffa-109277744778/ss"
"https://subscribe.fastsocks.xyz/api/v1/client/subscribe?token=f97e106e0ffd3eddb203e1fd21acfb7b"
"https://subscribe.fastsocks.xyz/api/v1/client/subscribe?token=d6681ca8e218af8f2ae0699e542e419c#Fastsoks"
"https://subscribe.fastsocks.xyz/api/v1/client/subscribe?token=9f0fb26b13d8f4f3063fcf8c46734523"
"https://zzz.zywn.cloudns.org"
"https://weiss2.jiekes.one"
"https://yyds.emovpn.top/api/v1/client/subscribe?token=e3564accfb797578dc8251fc07207abe"
"https://files.catbox.moe/3x5t1j.yaml"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWYylkm8vxM?C9?ckcx4iZb7xYOjutThhAJbeIr6dK9RCW/k2gpvHMO1ZqF4q/467p60qjbZ9onpGFq9rZLdj5GEGw2Dqiqz6w0LgWvaZQv2nU0Z6bUg9UAc"
"https://run-s2.jiedianxielou.workers.dev/api/v1/client/subscribe?token=87a8e50e60714196b26220db01575aee"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki1thMuE9/M?ZFQsebrxYbTi4iE0VYGQM6fbcpNcF/YzjpDda7Ffv0867pWwoPdhlrJzqSkdSq86O?ZltjANxDri2qOtmBOwV/eYQfjxAUImOE49Ww"
"https://suo.st/SeozNv7"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vx93Crew4KBsoZOfgfq?5unN0W8KYJqCAK9EGFuk5mZfLIf1eslc88sHg/P1zzet3/iBNRPg9ZuJhsD8MwTvo26uqmESxVa3IQg"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWYylkmY9wdeNu?lldhAjd?X7Z?vvuSx1Uc2EbK?EbY0FRbU5h5fMKrYFrkk775?grKpwxq15rHEVTvlkYOsxuWQOlDq92P?twxe2VP2fHf6jW0F7Zh9oXAH64g5T45awutQDyLQI3vBwHrXVZ?idIAA1eIqTF56xqGuI/bXiAUGWaRy68fUUh2ZA5g"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWYylkmQ?08?Fr7FlYBs?ZartZ6j94iE0VYGXL7eQd9cRFfZ13sidKbNDsF5g5ci4tfBnjeZ6rmcPTqowY6E4p2JHgz21i6av"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vx93Cres?NFcuf6Wub7b/4zRqF82dKquacI0AAfgpiIzAJqcVqVMy?ZLvpv0lyL10pncYF/lpY7RiuDIIwT2/1qz7yBnjVPedRfM"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki04y5GftOooKA0iYOfgfq?5unN0W8KYJqCAK9EGFuk5mZfLIf1eslc88sHlp/khzely/3FNR/w6MrBnsTYGwmnvjK2tz0G2AKmZRQ"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0s29GPsfRldRs?P6nxZ?ng/W04VMeULbrbd9cRB/kogpzMe7ZFtlk3oZrk/f9xn?sm9iIdFvlkMOFlsmRbzzrvja6vnhfhWqqY"
"https://tz.vfkum.website/api/v1/client/subscribe?token=495b8f8540a275a58abc64f93ea737f0"
"https://a.jiedianxielou.workers.dev/api/v1/client/subscribe?token=UjBGOXVrdFBKYzlqdnBCdThOZUx1b2xoT1loVW41MU0vbDFzbTl5ZmdUN2JqUkJNVW5wT3BuU2hZWTdPMGdmN28wRmN2enExMjR0ejBTU0gvZVllQ1RLWkhRVHpyN0tIV2kyMjBpNGdNQT09"
"https://0d2th.no-mad-world.club/link/dacqbivsqysnpzlq?clash=3&amp;extend=1"
"https://www.dabai.in/link/qrWBdYEZPKr61KkM?list=shadowrocket"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0429GLoPUuKA0/f6LgYLHl4joiQoGQM6fbcpNcF/YzjpDda7Ffv0867pWwoPdhlrJzqSkaFfttZus15WNdz23p362syxTlVK3PQP2iBxx6axQ8XQ"
"https://dzpd.jiedianxielou.workers.dev/api/v1/client/subscribe?token=bf64cd2b19ee10e66068fd94e335af79"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki09wtbd97R/N0h7Jub5d7y5rTIyF9jAbK2YbccdALUpnpzaJ7BDv1lm6JO5oKYoyu4m8yAeEv8/YbM25TMJz2u9jautmULtVfeYHPz0VkY"
"https://ymzx.jiedianxielou.workers.dev/api/v1/client/subscribe?token=8dfd36317be546ce993d2fc792cbe270"
"https://www.dabai.in/link/CBD3dq3z8U1eSIwD?list=shadowrocket"
"https://xf88j.no-mad-world.club/link/HtJ7xKqcaniqXvgV?clash=3"
"https://a.jiedianxielou.workers.dev/api/v1/client/subscribe?token=UjBGOXVrdFBKYzl0dE04ODdacUFzOTlrTU04RGtOWk0vRUZzMGNUYWdTN0NoZ1pCVkR4ZnRpbW1iWmZDM2wvd3RVeFY3ekM4aHRwNmhIS0UrYkFhQlRHY1NBZWdxYnlEVkNlK2lpRW5aZ1M3RWN0Y1VvVT0"
"https://mc.jiedianxielou.workers.dev/api/v1/client/subscribe?token=114514"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0rxcjd764pbx4sebrxYbTi4Sc3XdiULbqcKdEGFrQuhI6GJbJD8kpos5??rK17jfZlsnYIELs1YLdv9WhUkjbm2q2omhbnAffOQf?mB0YvaE0yUAP68R8ftdzq8IlQy7M"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0xx8yFuq4uZwo0d6f0fKq4tDshF8KYLaXbTZsHNtkvpIfhFKdrinI35JuL/PFEv51OrSE2Q4YZUOpv4mhRkTG80vrylw"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0/2taCuK4jcxg6daGsbar5uSZ1S8aeM?GVdMtcAqt1iJLAIaxe8k8s/o?xt6F3nOZiqH8eHfRuZuNp5zNdxGnp3K/6zhntVarJQav3BxUrbx1vXFH8pw"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0229GItvUycxd1KObtZ6Dz4yMrUYGHcuGXaMsWGu51mIvLN6FYtF48o4i9rq17xL8j8iRLRqs9Y7BnsTMNzmDojvr/zEHlU/fPRv6kAhMm"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0y296DvellchY9P6bob6mpuC0wXcDMJa/EYZcWTKNq0sbNcPMSvgw4q8SzoKonz?Bw9HFDSv8"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0o18yY9?Iicx8haeb1Yba5oCs1U4HECZ/NRe42AsAMgZDNCoVn4l81/Y?6?Pk"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0xx8yFuq4uZwo0d6f0fKq4tDshF8KYLaXbSuk?G90c3ar5cqZ8vmYQ5LqnqY5btup3q39CA4Yzc?Nv4mhRkTG80vrylw"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vg5GOt/A?ZBUkc7v0bOj1oy90Wd6YbLjFK8EfHf80n9HaMaBZvk4w/pntsad?nLcr83EZRqpoN7czuDIGxGjj16v8yBjjAPieF66gUBwtaRQ"
"https://a.jiedianxielou.workers.dev/api/v1/client/subscribe?token=bHl6RldjV3draTAyMjlHSXR2VW9haFk0ZE9iNWQ3eTVyVEl5RjlqQWJLMlliY2NkQUxVcG5wemFKN0JEdjFsbTZKTzVvS1lvenVCMW9TQWZTcW8vWStWZ3VUQmF6anJwMksrbXloTGhWS25KRWY2cUFVWT0"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWYylkmY13NiVrOV4KAg0equvdr/s4yMrUYGHcuGXaMsWGu51mIvLN6FYtF48o4i9rq17xLwg9XVOQf46Z?tguWIIw2Dt2aKtyhPiBPbLEv?jVBB7"
"https://dzpd.jiedianxielou.workers.dev/?clash=1"
"https://api.sub-200.club/link/KB1m4EHFEP4KbJLi?clash=3"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0rxcjCqvU4cxohf73lIK/4qi10Wd6YbLjFK8EfHf80n9HaMaBZvk4w/pntsad?nLcr9i0aFfA6ZupmsT4Pkmzj1/mow0HnBPvLFavzVRMqPx4"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vx93B6bFlMU96Jf61IL7vtm06SMfeNf/bZ84aEfQuxI3cJrFJr1U7?cOmqqNwl?R0oSNDQPk?M?Q152NekT7tjKz8nxezVKrOFPKkBhwuOA"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWYylkmY13NiVrOV5KAg0equvdr/s4yMrUYGHcuGXaMsWGu51mIvLN6FYtF48o4i9rq17xOwjpXFKSvg9ZrFi4j4Ozm3o2PqmyRPjUPzPRvv3UxZ/"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0xx8yFuq4uZwo0d6f0fKq4tDshF8KYLaXbReQeHesu36j9DY4YtkU96pii94VYsuogt1E9PK0LTKdv4mhRkTG80vrylw"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vx93e9/MmZxUhY7zzb7H0qTApQYCSLKPbZdIaW?xrxJ3FLadEqRMq6Z6hprp8m7wps3sQFqdhO?Zl4jYGw2vo3qmpmBbhW/abFK6iVREsak1pXVz78EU"
"https://api.sub-300.club/link/Wo5Nrr0QWszb2wcw?clash=3&amp;extend=1"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vy8aC9/gyfFYsYKGuePe5ry4yXcCFbL2BZtEQBvM4jsHdK6lPswFo/sjr9vAmweAupSZIS/ltYOdptzIHwWG62fj8yhKxVQ"
"https://a.jiedianxielou.workers.dev/api/v1/client/subscribe?token=UjBGOXVrdFBKYzlvNDRsNHQ4eUVzTVZzSnBRZng5Z003UjVranR2RTJIeUJqQTlHUlgxWTdEaWdiSmJJemxPdHBCeEs1VFhrMFlKNjBYblRxTDBhQ1RPYkdWU20vdXJXQUMyd2lISW5ZRmUxUWNoV0NOUlZDMGc9"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vnNSNteEqKBQoP76yIbXjrjE4SpGYJ/PFPZcWQv482s?Qd/Ye6V1r/Zrl9aojwbgmoidJQPBtZw"
"https://cb.dabai.in/link/ogzgogtsbubws4nv?list=shadowrocket"
"https://k61kz.no-mad-world.club/link/lZnnLLD3WHfMrM40?clash=3&amp;extend=1"
"https://a.jiedianxielou.workers.dev/api/v1/client/subscribe?token=UjBGOXVrdFBKYzl0dE5SK3M5Nk84Tkp2T2M0YW1jVk02d0FxbmQ2Q3l5UGF3QkJhUW1CUHNTSzNhOXJmMDFHcXJ4NE51VGpsaVlwMGgzbUgvT1pLQkRMTUhRS2xwYnFEVUNtMzN5OTBabEhwRVE9PQ"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0vx93d9/Qiaxwjdb7kfKX?rSw8Xd3fIKGZK8MDHbUs2tHKKKtPs0h274mwtqtnkLtz?GAUGKwyP7YyuDEMlD242/mqw0PjUavMF/LzUhR7PxRuXgf?okRH"
"https://m4y2z.no-mad-world.club/link/NornheyemazUtarM?clash=3"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki09wtbd97R/N0h7Jub5d7y5rTIyF9jAbK2YbccdALUpnpzaJ7BDv1lm6JO5oKYoyOAu/i0fFq9vNuRj4zBazjrsiqL/wxHsUfifQvmkUBw"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki041NifveYsKB4le6Lnaaz9qCQ8UNybJamcbtQRGvd0iJjNa6NatBMvrdOxqaFwl605tGEZAKoua7A1vnNQnD210qL6yRnjBv/IR6v2AUctaBg9Xgb/?Rwf5da3?dlQlehP"
"https://b.jiedianxielou.workers.dev/api/v1/client/subscribe?token=lyzFWcWwki0708qf9?wkalYsYKGuePe5ry4yXcCFbL2BZtEQBvM4jsHdK6lPswFg?Z6z/K0hzuAk9CYZRPo5O7ZptTUHxD3s2Kj4mRe0Ww=="
"https://6yb3xq.dness.top/api/v1/client/subscribe?token=806af1bab2cc27eb02c2cf9ec1e9f7b9"
"https://fz9qin.cluobotu.xyz/api/v1/client/subscribe?token=8dd1ac6ebbad08764e2514382043ed1b"
"http://novantunnel.life"
"https://ap.niaodi.top/niao?token=cdaa1b1f44005a4ed020ea98e001d0c5"
"https://edu.dianping.men/iv/verify_mode.htm?token=daaad892792bcfc3b31a62a66c7ffe88"
"https://anft4s.cluobotu.xyz/api/v1/client/subscribe?token=8dd1ac6ebbad08764e2514382043ed1b"
"https://suo.yt/swgmoew"
"https://aq.louwangzhiyu.xyz/api/v1/client/subscribe?token=60ea712bdae276ada7d4a60bf98992e4"
"https://yx5je8.fluobotu.xyz/api/v1/client/subscribe?token=8dd1ac6ebbad08764e2514382043ed1b"
"https://www.louwangzhiyu.xyz/api/v1/client/subscribe?token=8d4b6141011de1d68e5aad95d6a61329"
"https://0s1tn4.dness.top/api/v1/client/subscribe?token=806af1bab2cc27eb02c2cf9ec1e9f7b9"
"https://uthz8n.dness.top/api/v1/client/subscribe?token=806af1bab2cc27eb02c2cf9ec1e9f7b9"
"https://update.glados-config.com/v2ray/187948/832f9c850ada3f45"
"https://update.glados-config.com/v2ray/207707/5babe53ac574be0b"
"https://ch.owokkvsxks.store/api/v1/client/subscribe?token=ad180e3b9514176a8cb26bf2962d5f1e"
"https://4j99dr.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://vbqrlo.longonesub.xyz/api/v1/client/subscribe?token=751c31198bdd867e505edac3fb45d01d"
"https://9lkyfh.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://bujidao.cc/sub?key=KK7BTWJTpqY4bdO6R3qVu0qLWaAn9WRk"
"https://rapid-salad29f0.afrance.fr"
"https://b.zhangyongxin.top"
"https://kf2d8j.longonesub.xyz/api/v1/client/subscribe?token=751c31198bdd867e505edac3fb45d01d"
"http://jdzh.justn.nyc.mn"
"https://bujidao.cc/sub?key=vt8Qlku9OczyJt6JI1Eqb6ZeQlgehqEo"
"https://p2ce09.longonesub.xyz/api/v1/client/subscribe?token=751c31198bdd867e505edac3fb45d01d"
"https://4b8kse.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://sqhgq8.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://doone0701.xn--wqr30o34q.xn--io0a7i/api/v1/client/subscribe?token=751c31198bdd867e505edac3fb45d01d"
"http://b.zhangyongxin.top"
"https://muisgq.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://sub.scp-nsc.top/base64"
"https://jdzh.justn.nyc.mn"
"https://bujidao.cc/sub?key=qAmvoST9npYLEgOzq0RMqWhbqBYZoB9D"
"https://bujidao.cc/sub?key=XOfnIze0b27ESmztFIuLkfwF4XHZ7qSA"
"http://rapid-salad29f0.afrance.fr"
"http://mogui.yangmaoshan.dynv6.net"
"https://mysubpro.pages.dev/sub_clash.yaml"
"https://4iwg7p.babaivip.top/api/v1/client/subscribe?token=0631b0e70e123fd5c1bb9ff2bff2cda6"
"https://af078381-fcf9-457a-b03a-7bfaf506cd0b.xn--l6qx3lcvp58x.com/api/v1/client/subscribe?token=536c81b786085e0e5270db4185d21036"
"https://cpdd.one/sub?token=004c8f491fd34b029cd81badf89f8ced"
"https://my5353.com/sCdJh"
"https://v1.mk/IycgiNh"
"https://cdn.justn.nyc.mn"
"https://qq.xlm.plus/api/v1/client/subscribe?token=9e5db95336ab586ac6c4e2306c4d25a9"
"https://s.sdncimcin.xyz/link/jYs6aCv2KQ2uGtX7?sub=3"
"http://cdn.justn.nyc.mn"
"https://owo.o00o.ooo/ooo"
"https://aa.dabai.in/link/6hqEY4qjCts48S3y?sub=3"
"https://config.huojian111.com/link/57BXs2kcnyMZ1sJ3?sub=3"
"https://kcsub.vip/link/SUwJ25eNRnIqvx5W?clash=1"
"http://cfsub.318131.xyz"
"https://gitlab.com/ioshkj/quantumultx/-/raw/main/Shadowrocket/wyy.txt"
"https://sub.xinyo.vip/api/v1/client/subscribe?token=3378f3d5f9ab4d07d898ecb9132546a7"
"https://mianfei7.wosishangdi.cn.eu.org"
"https://vless.cmliussss.net"
"https://vless.xcxh.cf"
"https://sub.lianghao.tk"
"https://hwpr.291519643.xyz"
"https://api.xinyo.vip/api/v1/client/subscribe?token=5a563d7330dd13ce16ec909ea4257548"
"https://pastebin.com/raw/vXbMV9NT"
"https://cfsub.318131.xyz"
"https://api.xinyo.vip/api/v1/client/subscribe?token=731485d80bbbde226e16ffac57a57554"
"https://b.bbydy.org/api/v1/client/subscribe?token=b5cc7efa2d437b688b2d603da9639090"
"http://sub.lianghao.tk"
"https://api-hx.02000.net/api/v1/client/subscribe?token=9f44dff9e7a82425fc71e78c9d79fbb1"
"http://sub.oralyc.nyc.mn"
"https://cfsub.xuanyu.news"
"https://v1.mk/gkn8PEI"
"http://hwpr.291519643.xyz"
"https://sub.xinyo.vip/api/v1/client/subscribe?token=afab256888ae6487f2287d22b21cb779"
"https://api.zuanshivpn.cn/subscribe/shadowrocket/MGNmNTIwMTYtYmE5OC0zMTlkLWRlOGMtODRkYmZhYzljY2Nj"
"https://s.sdncimcin.xyz/link/0npKu0hlzUbbjI26?clash=1"
"http://vless.cmliussss.net"
"https://flying.flyfree.sbs"
"https://api.xinyo.vip/api/v1/client/subscribe?token=bb57e2195a6cabe24ed9469b3669aa0d"
"https://api.xinyo.vip/api/v1/client/subscribe?token=b0e5f918cf3c088dcfa65bf1f0a40ba1"
"https://api.xinyo.vip/api/v1/client/subscribe?token=32766ad77e22239683fc3b9e2a06f4bd"
"https://renshui.so-fast.org/link/mLN5tg7tkAVJiUCQ?sub=3&amp;extend=1"
"http://flying.flyfree.sbs"
"https://vless.venusir.com"
"https://kcsub.vip/link/U3q6DvpKNpIHVeOi?clash=1"
"https://sub.091793.xyz"
"https://api.xinyo.vip/api/v1/client/subscribe?token=825684aa7107efeabe525c12bd10bd02"
"https://sub.xinyo.vip/api/v1/client/subscribe?token=191ff749aef5fc340847cb7b846e8be1"
"https://s.sdncimcin.xyz/link/lNvdH2iRZpxj2nmL?clash=1"
"https://sub.dovia.eu.org"
"http://sub.091793.xyz"
"http://vless.xcxh.cf"
"http://trojan.cmliussss.net"
"https://sub.kxswxc.eu.org"
"https://1321078938-11mmjf3qkb-hk.scf.tencentcs.com/api/v1/client/subscribe?token=cb1270a6aa0980c4de79b49aad8098f7"
"http://all.124396.xyz"
"https://cloudfront-cdn-hk-iplc1.com/sub/r/fH99wqHCoMKIwodrwqTCtsK5wr12w5PDncK_w419w4PDnMKXwp4=/"
"http://cfsub.xuanyu.news"
"https://sub.oralyc.nyc.mn"
"http://sub.leisureea.com"
"http://vless.venusir.com"
"https://sub.larson-chen.eu.org"
"https://trojan.cmliussss.net"

)

# 配置参数
PARALLEL_JOBS=10    # 并行测试的节点数量
CONNECT_TIMEOUT=5   # nc 连接超时时间 (秒)

# 日志函数
log() {
    local level=$1 # INFO, WARN, ERROR
    shift
    echo "[$level] $(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 定义关联数组存储上次失败的节点
declare -A FAILED_NODES
SKIPPED_COUNT=0 # 用于统计跳过的节点数量

# 读取上次失败的节点（如果文件存在）
load_failed_nodes() {
    if [ -f "$FAILED_FILE" ]; then
        log INFO "读取上次失败的节点文件: $FAILED_FILE"
        while IFS= read -r node; do
            # 跳过空行、注释和分隔符
            [[ -z "$node" || "$node" =~ ^# || "$node" =~ ^-*$ ]] && continue
            # 使用节点链接作为键，标记为失败
            FAILED_NODES["$node"]=1
        done < "$FAILED_FILE"
        log INFO "加载了 ${#FAILED_NODES[@]} 个上次失败的节点"
    else
        log INFO "未找到上次失败的节点文件: $FAILED_FILE"
    fi
}

# 检查依赖
check_dependencies() {
    command -v dig >/dev/null 2>&1 || {
        log ERROR "dig 命令未找到，请确保安装 dnsutils（例如：sudo apt-get install dnsutils）"
        exit 1
    }
    command -v nc >/dev/null 2>&1 || {
        log ERROR "nc 命令未找到，请确保安装 netcat（例如：sudo apt-get install netcat）"
        exit 1
    }
    command -v curl >/dev/null 2>&1 || {
        log ERROR "curl 命令未找到，请确保安装 curl"
        exit 1
    }
    command -v sort >/dev/null 2>&1 || {
        log ERROR "sort 命令未找到"
        exit 1
    }
    command -v wc >/dev/null 2>&1 || {
        log ERROR "wc 命令未找到"
        exit 1
    }
}

# 核心函数：测试单个节点连接性
# 此函数在子进程中运行，并通过标准输出返回结果
test_single_node() {
    local NODE_LINK="$1"
    local LOG_PREFIX="[TEST]" # 用于在日志中区分，并非实际写入结果文件

    local IP=""
    local PORT=""
    local HOSTNAME_OR_IP=""

    # 提取 IP/Hostname 和 Port
    if [[ "$NODE_LINK" =~ ^(vless|vmess|trojan|hy2):\/\/(.+@)?([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
        HOSTNAME_OR_IP="${BASH_REMATCH[3]}"
        PORT="${BASH_REMATCH[4]}"
    elif [[ "$NODE_LINK" =~ ^ss:// ]]; then
        # 尝试直接从URL中匹配 hostname:port
        if echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | grep -qE '.'; then
            HOSTNAME_OR_IP=$(echo "$NODE_LINK" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | cut -d'@' -f2 | cut -d':' -f1)
            PORT=$(echo "$NODE_HOST_PORT" | grep -oE '@([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+)' | head -n 1 | cut -d':' -f2)
        else
            # 尝试base64解码
            local BASE64_PART=$(echo "$NODE_LINK" | sed 's/ss:\/\///' | cut -d'@' -f1)
            local DECODED_PART=$(echo "$BASE64_PART" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [[ "$DECODED_PART" =~ ([0-9a-zA-Z.-]+\[?[0-9a-fA-F:]+\]?):([0-9]+) ]]; then
                HOSTNAME_OR_IP="${BASH_REMATCH[1]}"
                PORT="${BASH_REMATCH[2]}"
            fi
        fi
    fi

    if [ -z "$HOSTNAME_OR_IP" ] || [ -z "$PORT" ]; then
        log WARN "$LOG_PREFIX - 无法从链接中解析 IP 或端口: $NODE_LINK"
        echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
        return
    fi

    # 如果是 IP 地址（IPv4 或 IPv6），直接使用
    if [[ "$HOSTNAME_OR_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$HOSTNAME_OR_IP" =~ ^\[?[0-9a-fA-F:]+\]?$ ]]; then
        IP="$HOSTNAME_OR_IP"
    else
        # 否则，解析域名
        # log INFO "$LOG_PREFIX 尝试解析域名: $HOSTNAME_OR_IP" # 并行时日志会非常多，此处可省略
        RESOLVED_IP=$(dig +short "$HOSTNAME_OR_IP" A "$HOSTNAME_OR_IP" AAAA | head -n 1)
        if [ -n "$RESOLVED_IP" ]; then
            IP="$RESOLVED_IP"
            log INFO "$LOG_PREFIX - 解析结果: $HOSTNAME_OR_IP -> $IP"
        else
            log WARN "$LOG_PREFIX - 无法解析域名: $HOSTNAME_OR_IP (原始链接: $NODE_LINK)"
            echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
            return
        fi
    fi

    log INFO "$LOG_PREFIX 正在测试节点连接: $IP:$PORT (来自 $NODE_LINK)"
    nc -z -w "$CONNECT_TIMEOUT" "$IP" "$PORT" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log INFO "$LOG_PREFIX - 结果: 成功连接到 $IP:$PORT"
        echo "SUCCESS:$NODE_LINK" # 输出成功标记和节点链接到 stdout
    else
        log WARN "$LOG_PREFIX - 结果: 无法连接到 $IP:$PORT (可能被防火墙阻止或服务未运行)"
        echo "FAILED:$NODE_LINK" # 输出失败标记和节点链接到 stdout
    fi
}

# 导出函数和变量，以便 xargs 的子进程能够访问它们
export -f test_single_node
export -f log
export LOG_FILE
export CONNECT_TIMEOUT

# --- 主逻辑开始 ---
log INFO "开始节点连接性测试..."
mkdir -p "$OUTPUT_DIR"

# 清空并初始化输出文件 (只保留头部，实际节点数据将在后面追加)
echo "# Successful Nodes (Updated by GitHub Actions at $(date))" > "$SUCCESS_FILE"
echo "-------------------------------------" >> "$SUCCESS_FILE"
echo "# Failed Nodes (Updated by GitHub Actions at $(date))" > "$FAILED_FILE"
echo "-------------------------------------" >> "$FAILED_FILE"

# 检查依赖
check_dependencies

# 加载上次失败的节点 (主进程加载)
load_failed_nodes

# 下载并合并节点配置文件
log INFO "下载并合并节点配置文件..."
for url in "${NODE_SOURCES[@]}"; do
    log INFO "  - 正在下载: $url"
    curl -sL --retry 3 --retry-delay 2 "$url" >> "$MERGED_NODES_TEMP_FILE"
    if [ $? -ne 0 ]; then
        log WARN "  - 未能从 $url 下载文件"
    fi
done

# 检查合并后的临时文件是否为空
if [ ! -s "$MERGED_NODES_TEMP_FILE" ]; then
    log ERROR "未能下载任何节点配置文件，或所有文件都为空"
    rm -f "$MERGED_NODES_TEMP_FILE"
    rm -f "$ALL_TEST_RESULTS_TEMP_FILE" # 清理新生成的临时文件
    exit 1
fi

# 去重合并后的节点
sort -u "$MERGED_NODES_TEMP_FILE" -o "$MERGED_NODES_TEMP_FILE"
log INFO "所有配置文件下载并合并成功（去重后），开始解析节点并测试连接性..."

# 开始并行测试节点
log INFO "开始并行测试 ${PARALLEL_JOBS} 个节点..."

# 1. 预处理节点：将上次失败的节点直接标记为 FAILED 并写入结果临时文件
# 2. 未跳过的节点通过管道传递给 xargs 进行并行测试
# 3. xargs 将 test_single_node 的所有输出（SUCCESS/FAILED 标记的节点链接）收集到 ALL_TEST_RESULTS_TEMP_FILE
cat "$MERGED_NODES_TEMP_FILE" | grep -vE '^(#|--|$)' | while IFS= read -r NODE_LINK; do
    if [[ -n "${FAILED_NODES[$NODE_LINK]}" ]]; then
        ((SKIPPED_COUNT++))
        echo "FAILED:$NODE_LINK" >> "$ALL_TEST_RESULTS_TEMP_FILE" # 将跳过的节点直接写入结果临时文件
    else
        echo "$NODE_LINK" # 非跳过节点传递给 xargs 进行测试
    fi
done | xargs -P "$PARALLEL_JOBS" -I {} bash -c 'test_single_node "$@"' _ {} >> "$ALL_TEST_RESULTS_TEMP_FILE" # test_single_node 的 stdout 重定向到此文件

# 清理合并后的原始节点列表临时文件
rm -f "$MERGED_NODES_TEMP_FILE"

# 处理所有测试结果，填充 SUCCESS_FILE 和 FAILED_FILE
log INFO "处理所有测试结果并写入最终文件..."

# 从 ALL_TEST_RESULTS_TEMP_FILE 中提取成功和失败的节点
# 使用 cut -d':' -f2- 来获取冒号后面的完整链接，因为链接中可能有冒号
SUCCESS_NODES_RAW=$(grep '^SUCCESS:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2-)
FAILED_NODES_RAW=$(grep '^FAILED:' "$ALL_TEST_RESULTS_TEMP_FILE" | cut -d':' -f2-)

# 将去重后的成功节点追加到 SUCCESS_FILE
if [ -n "$SUCCESS_NODES_RAW" ]; then
    echo "$SUCCESS_NODES_RAW" | sort -u >> "$SUCCESS_FILE"
fi

# 将去重后的失败节点追加到 FAILED_FILE
if [ -n "$FAILED_NODES_RAW" ]; then
    echo "$FAILED_NODES_RAW" | sort -u >> "$FAILED_FILE"
fi

# 清理所有测试结果的临时文件
rm -f "$ALL_TEST_RESULTS_TEMP_FILE"

log INFO "所有节点连接性测试完成。成功节点已保存到 $SUCCESS_FILE"
log INFO "失败节点已保存到 $FAILED_FILE"

# 统计信息
# 统计时跳过头部注释和分隔符行
success_nodes_count=$(grep -vE '^(#|--|$)' "$SUCCESS_FILE" 2>/dev/null | wc -l || echo 0)
failed_nodes_count=$(grep -vE '^(#|--|$)' "$FAILED_FILE" 2>/dev/null | wc -l || echo 0)
total_processed_nodes=$((success_nodes_count + failed_nodes_count + SKIPPED_COUNT))

log INFO "测试统计："
log INFO "  - 总处理节点数: $total_processed_nodes"
log INFO "  - 成功连接节点数: $success_nodes_count"
log INFO "  - 失败节点数: $failed_nodes_count"
log INFO "  - 跳过上次失败的节点数: $SKIPPED_COUNT"

# --- Git 推送逻辑 ---
log INFO "开始将结果推送到 GitHub 仓库..."

# 配置 Git
git config user.name "GitHub Actions"
git config user.email "actions@github.com"

# 检查是否有更改
# git diff --quiet --exit-code HEAD "$SUCCESS_FILE" "$FAILED_FILE" 比较的是工作区和HEAD的差异
# 如果文件内容只更新了时间戳，这个检查可能会通过，导致不提交
# 为了确保即使只有时间戳也提交，可以简化为直接 add/commit，让 git 自己判断是否有实际内容变化
git add "$SUCCESS_FILE" "$FAILED_FILE"
if ! git commit -m "Update node connectivity results (automated by GitHub Actions)"; then
    log INFO "没有新的节点连接性结果需要提交。"
else
    # 设置远程仓库URL，使用 GitHub Actions 提供的 token 进行认证
    git remote set-url origin "https://x-access-token:${GH_TOKEN_FOR_PUSH}@github.com/${GITHUB_REPOSITORY}.git"
    # 推送当前分支的HEAD到远程同名分支
    git push origin HEAD:${GITHUB_REF##*/} || {
        log ERROR "推送失败，请检查 Git 配置或网络"
        exit 1
    }
    log INFO "成功节点和失败节点已推送到 GitHub 仓库"
fi

log INFO "节点连接性测试和推送流程完成。"
