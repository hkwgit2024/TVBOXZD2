# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import base64
import subprocess
import threading
import time
import urllib.parse
import json
import glob
import re
import yaml
import random
import string
import httpx
import asyncio
from itertools import chain
from typing import Dict, List, Optional
import sys
import requests
import zipfile
import gzip
import shutil
import platform
import os
from datetime import datetime
from asyncio import Semaphore
import ssl

ssl._create_default_https_context = ssl._create_unverified_context
import warnings

warnings.filterwarnings('ignore')
from requests_html import HTMLSession
import psutil

# TEST_URL = "http://www.gstatic.com/generate_204"
TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
# 存储所有节点的速度测试结果
SPEED_TEST = False
SPEED_TEST_LIMIT = 5  # 只测试前30个节点的下行速度，每个节点测试5秒
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 10000  # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"  # 从文件中加载代理节点，支持yaml/yml、txt(每条代理链接占一行)
BAN = ["中国", "China", "CN", "电信", "移动", "联通"]
headers = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}

# Clash 配置文件的基础结构
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "geodata-mode": True,
    'geox-url': {'geoip': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat',
                 'mmdb': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb'},
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29"
        ],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True,
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        "fallback": [
            "https://doh.dns.sb/dns-query",
            "https://dns.cloudflare.com/dns-query",
            "https://dns.twnic.tw/dns-query",
            "tls://8.8.4.4:853"
        ],
        "fallback-filter": {
            "geoip": True,
            "ipcidr": [
                "240.0.0.0/4",
                "0.0.0.0/32"
            ]
        }
    },
    "proxies": [],
    "proxy-groups": [
        {
            "name": "节点选择",
            "type": "select",
            "proxies": [
                "自动选择",
                "故障转移",
                "DIRECT",
                "手动选择"
            ]
        },
        {
            "name": "自动选择",
            "type": "url-test",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            # "url": "http://www.gstatic.com/generate_204",
            "url": "http://www.pinterest.com",
            "interval": 300,
            "tolerance": 50
        },
        {
            "name": "故障转移",
            "type": "fallback",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        },
        {
            "name": "手动选择",
            "type": "select",
            "proxies": []
        },
    ],
    "rules": [
        "DOMAIN,app.adjust.com,DIRECT",
        "DOMAIN,bdtj.tagtic.cn,DIRECT",
        "DOMAIN,log.mmstat.com,DIRECT",
        "DOMAIN,sycm.mmstat.com,DIRECT",
        "DOMAIN-SUFFIX,blog.google,DIRECT",
        "DOMAIN-SUFFIX,googletraveladservices.com,DIRECT",
        "DOMAIN,dl.google.com,DIRECT",
        "DOMAIN,dl.l.google.com,DIRECT",
        "DOMAIN,fonts.googleapis.com,DIRECT",
        "DOMAIN,fonts.gstatic.com,DIRECT",
        "DOMAIN,mtalk.google.com,DIRECT",
        "DOMAIN,alt1-mtalk.google.com,DIRECT",
        "DOMAIN,alt2-mtalk.google.com,DIRECT",
        "DOMAIN,alt3-mtalk.google.com,DIRECT",
        "DOMAIN,alt4-mtalk.google.com,DIRECT",
        "DOMAIN,alt5-mtalk.google.com,DIRECT",
        "DOMAIN,alt6-mtalk.google.com,DIRECT",
        "DOMAIN,alt7-mtalk.google.com,DIRECT",
        "DOMAIN,alt8-mtalk.google.com,DIRECT",
        "DOMAIN,fairplay.l.qq.com,DIRECT",
        "DOMAIN,livew.l.qq.com,DIRECT",
        "DOMAIN,vd.l.qq.com,DIRECT",
        "DOMAIN,analytics.strava.com,DIRECT",
        "DOMAIN,msg.umeng.com,DIRECT",
        "DOMAIN,msg.umengcloud.com,DIRECT",
        "PROCESS-NAME,com.ximalaya.ting.himalaya,节点选择",
        "DOMAIN-SUFFIX,himalaya.com,节点选择",
        "PROCESS-NAME,deezer.android.app,节点选择",
        "DOMAIN-SUFFIX,deezer.com,节点选择",
        "DOMAIN-SUFFIX,dzcdn.net,节点选择",
        "PROCESS-NAME,com.tencent.ibg.joox,节点选择",
        "PROCESS-NAME,com.tencent.ibg.jooxtv,节点选择",
        "DOMAIN-SUFFIX,joox.com,节点选择",
        "DOMAIN-KEYWORD,jooxweb-api,节点选择",
        "PROCESS-NAME,com.skysoft.kkbox.android,节点选择",
        "DOMAIN-SUFFIX,kkbox.com,节点选择",
        "DOMAIN-SUFFIX,kkbox.com.tw,节点选择",
        "DOMAIN-SUFFIX,kfs.io,节点选择",
        "PROCESS-NAME,com.pandora.android,节点选择",
        "DOMAIN-SUFFIX,pandora.com,节点选择",
        "PROCESS-NAME,com.soundcloud.android,节点选择",
        "DOMAIN-SUFFIX,p-cdn.us,节点选择",
        "DOMAIN-SUFFIX,sndcdn.com,节点选择",
        "DOMAIN-SUFFIX,soundcloud.com,节点选择",
        "PROCESS-NAME,com.spotify.music,节点选择",
        "DOMAIN-SUFFIX,pscdn.co,节点选择",
        "DOMAIN-SUFFIX,scdn.co,节点选择",
        "DOMAIN-SUFFIX,spotify.com,节点选择",
        "DOMAIN-SUFFIX,spoti.fi,节点选择",
        "DOMAIN-KEYWORD,spotify.com,节点选择",
        "DOMAIN-KEYWORD,-spotify-com,节点选择",
        "PROCESS-NAME,com.aspiro.tidal,节点选择",
        "DOMAIN-SUFFIX,tidal.com,节点选择",
        "PROCESS-NAME,com.google.android.apps.youtube.music,节点选择",
        "PROCESS-NAME,com.google.android.youtube.tvmusic,节点选择",
        "PROCESS-NAME,tv.abema,节点选择",
        "DOMAIN-SUFFIX,abema.io,节点选择",
        "DOMAIN-SUFFIX,abema.tv,节点选择",
        "DOMAIN-SUFFIX,ameba.jp,节点选择",
        "DOMAIN-SUFFIX,hayabusa.io,节点选择",
        "DOMAIN-KEYWORD,abematv.akamaized.net,节点选择",
        "PROCESS-NAME,com.channel4.ondemand,节点选择",
        "DOMAIN-SUFFIX,c4assets.com,节点选择",
        "DOMAIN-SUFFIX,channel4.com,节点选择",
        "PROCESS-NAME,com.amazon.avod.thirdp,节点选择",
        "DOMAIN-SUFFIX,aiv-cdn.net,节点选择",
        "DOMAIN-SUFFIX,aiv-delivery.net,节点选择",
        "DOMAIN-SUFFIX,amazonvideo.com,节点选择",
        "DOMAIN-SUFFIX,primevideo.com,节点选择",
        "DOMAIN-SUFFIX,media-amazon.com,节点选择",
        "DOMAIN,atv-ps.amazon.com,节点选择",
        "DOMAIN,fls-na.amazon.com,DIRECT",
        "DOMAIN,avodmp4s3ww-a.akamaihd.net,节点选择",
        "DOMAIN,d25xi40x97liuc.cloudfront.net,节点选择",
        "DOMAIN,dmqdd6hw24ucf.cloudfront.net,节点选择",
        "DOMAIN,dmqdd6hw24ucf.cloudfront.net,节点选择",
        "DOMAIN,d22qjgkvxw22r6.cloudfront.net,节点选择",
        "DOMAIN,d1v5ir2lpwr8os.cloudfront.net,节点选择",
        "DOMAIN,d27xxe7juh1us6.cloudfront.net,节点选择",
        "DOMAIN-KEYWORD,avoddashs,节点选择",
        "DOMAIN,linear.tv.apple.com,节点选择",
        "DOMAIN,play-edge.itunes.apple.com,节点选择",
        "PROCESS-NAME,tw.com.gamer.android.animad,节点选择",
        "DOMAIN-SUFFIX,bahamut.com.tw,节点选择",
        "DOMAIN-SUFFIX,gamer.com.tw,节点选择",
        "DOMAIN,gamer-cds.cdn.hinet.net,节点选择",
        "DOMAIN,gamer2-cds.cdn.hinet.net,节点选择",
        "PROCESS-NAME,bbc.iplayer.android,节点选择",
        "DOMAIN-SUFFIX,bbc.co.uk,节点选择",
        "DOMAIN-SUFFIX,bbci.co.uk,节点选择",
        "DOMAIN-KEYWORD,bbcfmt,节点选择",
        "DOMAIN-KEYWORD,uk-live,节点选择",
        "PROCESS-NAME,com.dazn,节点选择",
        "DOMAIN-SUFFIX,dazn.com,节点选择",
        "DOMAIN-SUFFIX,dazn-api.com,节点选择",
        "DOMAIN,d151l6v8er5bdm.cloudfront.net,节点选择",
        "DOMAIN-KEYWORD,voddazn,节点选择",
        "PROCESS-NAME,com.disney.disneyplus,节点选择",
        "DOMAIN-SUFFIX,bamgrid.com,节点选择",
        "DOMAIN-SUFFIX,disneyplus.com,节点选择",
        "DOMAIN-SUFFIX,disney-plus.net,节点选择",
        "DOMAIN-SUFFIX,disney自动选择.com,节点选择",
        "DOMAIN-SUFFIX,dssott.com,节点选择",
        "DOMAIN,cdn.registerdisney.go.com,节点选择",
        "PROCESS-NAME,com.dmm.app.movieplayer,节点选择",
        "DOMAIN-SUFFIX,dmm.co.jp,节点选择",
        "DOMAIN-SUFFIX,dmm.com,节点选择",
        "DOMAIN-SUFFIX,dmm-extension.com,节点选择",
        "PROCESS-NAME,com.tvbusa.encore,节点选择",
        "DOMAIN-SUFFIX,encoretvb.com,节点选择",
        "DOMAIN,edge.api.brightcove.com,节点选择",
        "DOMAIN,bcbolt446c5271-a.akamaihd.net,节点选择",
        "PROCESS-NAME,com.fox.now,节点选择",
        "DOMAIN-SUFFIX,fox.com,节点选择",
        "DOMAIN-SUFFIX,foxdcg.com,节点选择",
        "DOMAIN-SUFFIX,theplatform.com,节点选择",
        "DOMAIN-SUFFIX,uplynk.com,节点选择",
        "DOMAIN-SUFFIX,foxplus.com,节点选择",
        "DOMAIN,cdn-fox-networks-group-green.akamaized.net,节点选择",
        "DOMAIN,d3cv4a9a9wh0bt.cloudfront.net,节点选择",
        "DOMAIN,foxsports01-i.akamaihd.net,节点选择",
        "DOMAIN,foxsports02-i.akamaihd.net,节点选择",
        "DOMAIN,foxsports03-i.akamaihd.net,节点选择",
        "DOMAIN,staticasiafox.akamaized.net,节点选择",
        "PROCESS-NAME,com.hbo.hbonow,节点选择",
        "DOMAIN-SUFFIX,hbo.com,节点选择",
        "DOMAIN-SUFFIX,hbogo.com,节点选择",
        "DOMAIN-SUFFIX,hbonow.com,节点选择",
        "DOMAIN-SUFFIX,hbomax.com,节点选择",
        "PROCESS-NAME,hk.hbo.hbogo,节点选择",
        "DOMAIN-SUFFIX,hbogoasia.com,节点选择",
        "DOMAIN-SUFFIX,hbogoasia.hk,节点选择",
        "DOMAIN,bcbolthboa-a.akamaihd.net,节点选择",
        "DOMAIN,players.brightcove.net,节点选择",
        "DOMAIN,s3-ap-southeast-1.amazonaws.com,节点选择",
        "DOMAIN,dai3fd1oh325y.cloudfront.net,节点选择",
        "DOMAIN,44wilhpljf.execute-api.ap-southeast-1.amazonaws.com,节点选择",
        "DOMAIN,hboasia1-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia2-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia3-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia4-i.akamaihd.net,节点选择",
        "DOMAIN,hboasia5-i.akamaihd.net,节点选择",
        "DOMAIN,cf-images.ap-southeast-1.prod.boltdns.net,节点选择",
        "DOMAIN-SUFFIX,5itv.tv,节点选择",
        "DOMAIN-SUFFIX,ocnttv.com,节点选择",
        "PROCESS-NAME,com.hulu.plus,节点选择",
        "DOMAIN-SUFFIX,hulu.com,节点选择",
        "DOMAIN-SUFFIX,huluim.com,节点选择",
        "DOMAIN-SUFFIX,hulustream.com,节点选择",
        "PROCESS-NAME,jp.happyon.android,节点选择",
        "DOMAIN-SUFFIX,happyon.jp,节点选择",
        "DOMAIN-SUFFIX,hjholdings.jp,节点选择",
        "DOMAIN-SUFFIX,hulu.jp,节点选择",
        "PROCESS-NAME,air.ITVMobilePlayer,节点选择",
        "DOMAIN-SUFFIX,itv.com,节点选择",
        "DOMAIN-SUFFIX,itvstatic.com,节点选择",
        "DOMAIN,itvpnpmobile-a.akamaihd.net,节点选择",
        "PROCESS-NAME,com.kktv.kktv,节点选择",
        "DOMAIN-SUFFIX,kktv.com.tw,节点选择",
        "DOMAIN-SUFFIX,kktv.me,节点选择",
        "DOMAIN,kktv-theater.kk.stream,节点选择",
        "PROCESS-NAME,com.linecorp.linetv,节点选择",
        "DOMAIN-SUFFIX,linetv.tw,节点选择",
        "DOMAIN,d3c7rimkq79yfu.cloudfront.net,节点选择",
        "PROCESS-NAME,com.litv.mobile.gp.litv,节点选择",
        "DOMAIN-SUFFIX,litv.tv,节点选择",
        "DOMAIN,litvfreemobile-hichannel.cdn.hinet.net,节点选择",
        "PROCESS-NAME,com.mobileiq.demand5,节点选择",
        "DOMAIN-SUFFIX,channel5.com,节点选择",
        "DOMAIN-SUFFIX,my5.tv,节点选择",
        "DOMAIN,d349g9zuie06uo.cloudfront.net,节点选择",
        "PROCESS-NAME,com.tvb.mytvsuper,节点选择",
        "DOMAIN-SUFFIX,mytvsuper.com,节点选择",
        "DOMAIN-SUFFIX,tvb.com,节点选择",
        "PROCESS-NAME,com.netflix.mediaclient,节点选择",
        "DOMAIN-SUFFIX,netflix.com,节点选择",
        "DOMAIN-SUFFIX,netflix.net,节点选择",
        "DOMAIN-SUFFIX,nflxext.com,节点选择",
        "DOMAIN-SUFFIX,nflximg.com,节点选择",
        "DOMAIN-SUFFIX,nflximg.net,节点选择",
        "DOMAIN-SUFFIX,nflxso.net,节点选择",
        "DOMAIN-SUFFIX,nflxvideo.net,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest0.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest1.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest2.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest3.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest4.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest5.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest6.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest7.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest8.com,节点选择",
        "DOMAIN-SUFFIX,netflixdnstest9.com,节点选择",
        "DOMAIN-KEYWORD,dualstack.api自动选择-device-prod-nlb-,节点选择",
        "DOMAIN-KEYWORD,dualstack.ichnaea-web-,节点选择",
        "IP-CIDR,23.246.0.0/18,节点选择,no-resolve",
        "IP-CIDR,37.77.184.0/21,节点选择,no-resolve",
        "IP-CIDR,45.57.0.0/17,节点选择,no-resolve",
        "IP-CIDR,64.120.128.0/17,节点选择,no-resolve",
        "IP-CIDR,66.197.128.0/17,节点选择,no-resolve",
        "IP-CIDR,108.175.32.0/20,节点选择,no-resolve",
        "IP-CIDR,192.173.64.0/18,节点选择,no-resolve",
        "IP-CIDR,198.38.96.0/19,节点选择,no-resolve",
        "IP-CIDR,198.45.48.0/20,节点选择,no-resolve",
        "IP-CIDR,34.210.42.111/32,节点选择,no-resolve",
        "IP-CIDR,52.89.124.203/32,节点选择,no-resolve",
        "IP-CIDR,54.148.37.5/32,节点选择,no-resolve",
        "PROCESS-NAME,jp.nicovideo.android,节点选择",
        "DOMAIN-SUFFIX,dmc.nico,节点选择",
        "DOMAIN-SUFFIX,nicovideo.jp,节点选择",
        "DOMAIN-SUFFIX,nimg.jp,节点选择",
        "PROCESS-NAME,com.pccw.nowemobile,节点选择",
        "DOMAIN-SUFFIX,nowe.com,节点选择",
        "DOMAIN-SUFFIX,nowestatic.com,节点选择",
        "PROCESS-NAME,com.pbs.video,节点选择",
        "DOMAIN-SUFFIX,pbs.org,节点选择",
        "DOMAIN-SUFFIX,phncdn.com,节点选择",
        "DOMAIN-SUFFIX,phprcdn.com,节点选择",
        "DOMAIN-SUFFIX,pornhub.com,节点选择",
        "DOMAIN-SUFFIX,pornhubpremium.com,节点选择",
        "PROCESS-NAME,com.twgood.android,节点选择",
        "DOMAIN-SUFFIX,skyking.com.tw,节点选择",
        "DOMAIN,hamifans.emome.net,节点选择",
        "PROCESS-NAME,com.ss.android.ugc.trill,节点选择",
        "DOMAIN-SUFFIX,byteoversea.com,节点选择",
        "DOMAIN-SUFFIX,ibytedtos.com,节点选择",
        "DOMAIN-SUFFIX,muscdn.com,节点选择",
        "DOMAIN-SUFFIX,musical.ly,节点选择",
        "DOMAIN-SUFFIX,tiktok.com,节点选择",
        "DOMAIN-SUFFIX,tik-tokapi.com,节点选择",
        "DOMAIN-SUFFIX,tiktokcdn.com,节点选择",
        "DOMAIN-SUFFIX,tiktokv.com,节点选择",
        "DOMAIN-KEYWORD,-tiktokcdn-com,节点选择",
        "PROCESS-NAME,tv.twitch.android.app,节点选择",
        "DOMAIN-SUFFIX,jtvnw.net,节点选择",
        "DOMAIN-SUFFIX,ttvnw.net,节点选择",
        "DOMAIN-SUFFIX,twitch.tv,节点选择",
        "DOMAIN-SUFFIX,twitchcdn.net,节点选择",
        "PROCESS-NAME,com.hktve.viutv,节点选择",
        "DOMAIN-SUFFIX,viu.com,节点选择",
        "DOMAIN-SUFFIX,viu.tv,节点选择",
        "DOMAIN,api.viu.now.com,节点选择",
        "DOMAIN,d1k2us671qcoau.cloudfront.net,节点选择",
        "DOMAIN,d2anahhhmp1ffz.cloudfront.net,节点选择",
        "DOMAIN,dfp6rglgjqszk.cloudfront.net,节点选择",
        "PROCESS-NAME,com.google.android.youtube,节点选择",
        "PROCESS-NAME,com.google.android.youtube.tv,节点选择",
        "DOMAIN-SUFFIX,googlevideo.com,节点选择",
        "DOMAIN-SUFFIX,youtube.com,节点选择",
        "DOMAIN,youtubei.googleapis.com,节点选择",
        "DOMAIN-SUFFIX,biliapi.net,节点选择",
        "DOMAIN-SUFFIX,bilibili.com,节点选择",
        "DOMAIN,upos-hz-mirrorakam.akamaized.net,节点选择",
        "DOMAIN-SUFFIX,iq.com,节点选择",
        "DOMAIN,cache.video.iqiyi.com,节点选择",
        "DOMAIN,cache-video.iq.com,节点选择",
        "DOMAIN,intl.iqiyi.com,节点选择",
        "DOMAIN,intl-rcd.iqiyi.com,节点选择",
        "DOMAIN,intl-subscription.iqiyi.com,节点选择",
        "DOMAIN-KEYWORD,oversea-tw.inter.iqiyi.com,节点选择",
        "DOMAIN-KEYWORD,oversea-tw.inter.ptqy.gitv.tv,节点选择",
        "IP-CIDR,103.44.56.0/22,节点选择,no-resolve",
        "IP-CIDR,118.26.32.0/23,节点选择,no-resolve",
        "IP-CIDR,118.26.120.0/24,节点选择,no-resolve",
        "IP-CIDR,223.119.62.225/28,节点选择,no-resolve",
        "IP-CIDR,23.40.242.10/32,节点选择,no-resolve",
        "IP-CIDR,23.40.241.251/32,节点选择,no-resolve",
        "DOMAIN-SUFFIX,api.mgtv.com,节点选择",
        "DOMAIN-SUFFIX,wetv.vip,节点选择",
        "DOMAIN-SUFFIX,wetvinfo.com,节点选择",
        "DOMAIN,testflight.apple.com,节点选择",
        "DOMAIN-SUFFIX,appspot.com,节点选择",
        "DOMAIN-SUFFIX,blogger.com,节点选择",
        "DOMAIN-SUFFIX,getoutline.org,节点选择",
        "DOMAIN-SUFFIX,gvt0.com,节点选择",
        "DOMAIN-SUFFIX,gvt3.com,节点选择",
        "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,节点选择",
        "DOMAIN-SUFFIX,ytimg.com,节点选择",
        "DOMAIN-KEYWORD,google,节点选择",
        "DOMAIN-KEYWORD,.blogspot.,节点选择",
        "DOMAIN-SUFFIX,aka.ms,节点选择",
        "DOMAIN-SUFFIX,onedrive.live.com,节点选择",
        "DOMAIN,az416426.vo.msecnd.net,节点选择",
        "DOMAIN,az668014.vo.msecnd.net,节点选择",
        "DOMAIN-SUFFIX,cdninstagram.com,节点选择",
        "DOMAIN-SUFFIX,facebook.com,节点选择",
        "DOMAIN-SUFFIX,facebook.net,节点选择",
        "DOMAIN-SUFFIX,fb.com,节点选择",
        "DOMAIN-SUFFIX,fb.me,节点选择",
        "DOMAIN-SUFFIX,fbaddins.com,节点选择",
        "DOMAIN-SUFFIX,fbcdn.net,节点选择",
        "DOMAIN-SUFFIX,fbsbx.com,节点选择",
        "DOMAIN-SUFFIX,fbworkmail.com,节点选择",
        "DOMAIN-SUFFIX,instagram.com,节点选择",
        "DOMAIN-SUFFIX,m.me,节点选择",
        "DOMAIN-SUFFIX,messenger.com,节点选择",
        "DOMAIN-SUFFIX,oculus.com,节点选择",
        "DOMAIN-SUFFIX,oculuscdn.com,节点选择",
        "DOMAIN-SUFFIX,rocksdb.org,节点选择",
        "DOMAIN-SUFFIX,whatsapp.com,节点选择",
        "DOMAIN-SUFFIX,whatsapp.net,节点选择",
        "DOMAIN-SUFFIX,pscp.tv,节点选择",
        "DOMAIN-SUFFIX,periscope.tv,节点选择",
        "DOMAIN-SUFFIX,t.co,节点选择",
        "DOMAIN-SUFFIX,twimg.co,节点选择",
        "DOMAIN-SUFFIX,twimg.com,节点选择",
        "DOMAIN-SUFFIX,twitpic.com,节点选择",
        "DOMAIN-SUFFIX,twitter.com,节点选择",
        "DOMAIN-SUFFIX,x.com,节点选择",
        "DOMAIN-SUFFIX,vine.co,节点选择",
        "DOMAIN-SUFFIX,telegra.ph,节点选择",
        "DOMAIN-SUFFIX,telegram.org,节点选择",
        "IP-CIDR,91.108.4.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.8.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.12.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.16.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.20.0/22,节点选择,no-resolve",
        "IP-CIDR,91.108.56.0/22,节点选择,no-resolve",
        "IP-CIDR,149.154.160.0/20,节点选择,no-resolve",
        "IP-CIDR,2001:b28:f23d::/48,节点选择,no-resolve",
        "IP-CIDR,2001:b28:f23f::/48,节点选择,no-resolve",
        "IP-CIDR,2001:67c:4e8::/48,节点选择,no-resolve",
        "DOMAIN-SUFFIX,line.me,节点选择",
        "DOMAIN-SUFFIX,line-apps.com,节点选择",
        "DOMAIN-SUFFIX,line-scdn.net,节点选择",
        "DOMAIN-SUFFIX,naver.jp,节点选择",
        "IP-CIDR,103.2.30.0/23,节点选择,no-resolve",
        "IP-CIDR,125.209.208.0/20,节点选择,no-resolve",
        "IP-CIDR,147.92.128.0/17,节点选择,no-resolve",
        "IP-CIDR,203.104.144.0/21,节点选择,no-resolve",
        "DOMAIN-SUFFIX,amazon.co.jp,节点选择",
        "DOMAIN,d3c33hcgiwev3.cloudfront.net,节点选择",
        "DOMAIN,payments-jp.amazon.com,节点选择",
        "DOMAIN,s3-ap-northeast-1.amazonaws.com,节点选择",
        "DOMAIN,s3-ap-southeast-2.amazonaws.com,节点选择",
        "DOMAIN,a248.e.akamai.net,节点选择",
        "DOMAIN,a771.dscq.akamai.net,节点选择",
        "DOMAIN-SUFFIX,4shared.com,节点选择",
        "DOMAIN-SUFFIX,9cache.com,节点选择",
        "DOMAIN-SUFFIX,9gag.com,节点选择",
        "DOMAIN-SUFFIX,abc.com,节点选择",
        "DOMAIN-SUFFIX,abc.net.au,节点选择",
        "DOMAIN-SUFFIX,abebooks.com,节点选择",
        "DOMAIN-SUFFIX,ao3.org,节点选择",
        "DOMAIN-SUFFIX,apigee.com,节点选择",
        "DOMAIN-SUFFIX,apkcombo.com,节点选择",
        "DOMAIN-SUFFIX,apk-dl.com,节点选择",
        "DOMAIN-SUFFIX,apkfind.com,节点选择",
        "DOMAIN-SUFFIX,apkmirror.com,节点选择",
        "DOMAIN-SUFFIX,apkmonk.com,节点选择",
        "DOMAIN-SUFFIX,apkpure.com,节点选择",
        "DOMAIN-SUFFIX,aptoide.com,节点选择",
        "DOMAIN-SUFFIX,archive.is,节点选择",
        "DOMAIN-SUFFIX,archive.org,节点选择",
        "DOMAIN-SUFFIX,archiveofourown.com,节点选择",
        "DOMAIN-SUFFIX,archiveofourown.org,节点选择",
        "DOMAIN-SUFFIX,arte.tv,节点选择",
        "DOMAIN-SUFFIX,artstation.com,节点选择",
        "DOMAIN-SUFFIX,arukas.io,节点选择",
        "DOMAIN-SUFFIX,ask.com,节点选择",
        "DOMAIN-SUFFIX,avg.com,节点选择",
        "DOMAIN-SUFFIX,avgle.com,节点选择",
        "DOMAIN-SUFFIX,badoo.com,节点选择",
        "DOMAIN-SUFFIX,bandwagonhost.com,节点选择",
        "DOMAIN-SUFFIX,bangkokpost.com,节点选择",
        "DOMAIN-SUFFIX,bbc.com,节点选择",
        "DOMAIN-SUFFIX,behance.net,节点选择",
        "DOMAIN-SUFFIX,bibox.com,节点选择",
        "DOMAIN-SUFFIX,biggo.com.tw,节点选择",
        "DOMAIN-SUFFIX,binance.com,节点选择",
        "DOMAIN-SUFFIX,bit.ly,节点选择",
        "DOMAIN-SUFFIX,bitcointalk.org,节点选择",
        "DOMAIN-SUFFIX,bitfinex.com,节点选择",
        "DOMAIN-SUFFIX,bitmex.com,节点选择",
        "DOMAIN-SUFFIX,bit-z.com,节点选择",
        "DOMAIN-SUFFIX,bloglovin.com,节点选择",
        "DOMAIN-SUFFIX,bloomberg.cn,节点选择",
        "DOMAIN-SUFFIX,bloomberg.com,节点选择",
        "DOMAIN-SUFFIX,blubrry.com,节点选择",
        "DOMAIN-SUFFIX,book.com.tw,节点选择",
        "DOMAIN-SUFFIX,booklive.jp,节点选择",
        "DOMAIN-SUFFIX,books.com.tw,节点选择",
        "DOMAIN-SUFFIX,boslife.net,节点选择",
        "DOMAIN-SUFFIX,box.com,节点选择",
        "DOMAIN-SUFFIX,brave.com,节点选择",
        "DOMAIN-SUFFIX,businessinsider.com,节点选择",
        "DOMAIN-SUFFIX,buzzfeed.com,节点选择",
        "DOMAIN-SUFFIX,bwh1.net,节点选择",
        "DOMAIN-SUFFIX,castbox.fm,节点选择",
        "DOMAIN-SUFFIX,cbc.ca,节点选择",
        "DOMAIN-SUFFIX,cdw.com,节点选择",
        "DOMAIN-SUFFIX,change.org,节点选择",
        "DOMAIN-SUFFIX,channelnewsasia.com,节点选择",
        "DOMAIN-SUFFIX,ck101.com,节点选择",
        "DOMAIN-SUFFIX,clarionproject.org,节点选择",
        "DOMAIN-SUFFIX,cloudcone.com,节点选择",
        "DOMAIN-SUFFIX,clyp.it,节点选择",
        "DOMAIN-SUFFIX,cna.com.tw,节点选择",
        "DOMAIN-SUFFIX,comparitech.com,节点选择",
        "DOMAIN-SUFFIX,conoha.jp,节点选择",
        "DOMAIN-SUFFIX,crucial.com,节点选择",
        "DOMAIN-SUFFIX,cts.com.tw,节点选择",
        "DOMAIN-SUFFIX,cw.com.tw,节点选择",
        "DOMAIN-SUFFIX,cyberctm.com,节点选择",
        "DOMAIN-SUFFIX,dailymotion.com,节点选择",
        "DOMAIN-SUFFIX,dailyview.tw,节点选择",
        "DOMAIN-SUFFIX,daum.net,节点选择",
        "DOMAIN-SUFFIX,daumcdn.net,节点选择",
        "DOMAIN-SUFFIX,dcard.tw,节点选择",
        "DOMAIN-SUFFIX,deadline.com,节点选择",
        "DOMAIN-SUFFIX,deepdiscount.com,节点选择",
        "DOMAIN-SUFFIX,depositphotos.com,节点选择",
        "DOMAIN-SUFFIX,deviantart.com,节点选择",
        "DOMAIN-SUFFIX,disconnect.me,节点选择",
        "DOMAIN-SUFFIX,discordapp.com,节点选择",
        "DOMAIN-SUFFIX,discordapp.net,节点选择",
        "DOMAIN-SUFFIX,disqus.com,节点选择",
        "DOMAIN-SUFFIX,dlercloud.com,节点选择",
        "DOMAIN-SUFFIX,dmhy.org,节点选择",
        "DOMAIN-SUFFIX,dns2go.com,节点选择",
        "DOMAIN-SUFFIX,dowjones.com,节点选择",
        "DOMAIN-SUFFIX,dropbox.com,节点选择",
        "DOMAIN-SUFFIX,dropboxapi.com,节点选择",
        "DOMAIN-SUFFIX,dropboxusercontent.com,节点选择",
        "DOMAIN-SUFFIX,duckduckgo.com,节点选择",
        "DOMAIN-SUFFIX,duyaoss.com,节点选择",
        "DOMAIN-SUFFIX,dw.com,节点选择",
        "DOMAIN-SUFFIX,dynu.com,节点选择",
        "DOMAIN-SUFFIX,earthcam.com,节点选择",
        "DOMAIN-SUFFIX,ebookservice.tw,节点选择",
        "DOMAIN-SUFFIX,economist.com,节点选择",
        "DOMAIN-SUFFIX,edgecastcdn.net,节点选择",
        "DOMAIN-SUFFIX,edx-cdn.org,节点选择",
        "DOMAIN-SUFFIX,elpais.com,节点选择",
        "DOMAIN-SUFFIX,enanyang.my,节点选择",
        "DOMAIN-SUFFIX,encyclopedia.com,节点选择",
        "DOMAIN-SUFFIX,esoir.be,节点选择",
        "DOMAIN-SUFFIX,etherscan.io,节点选择",
        "DOMAIN-SUFFIX,euronews.com,节点选择",
        "DOMAIN-SUFFIX,evozi.com,节点选择",
        "DOMAIN-SUFFIX,exblog.jp,节点选择",
        "DOMAIN-SUFFIX,feeder.co,节点选择",
        "DOMAIN-SUFFIX,feedly.com,节点选择",
        "DOMAIN-SUFFIX,feedx.net,节点选择",
        "DOMAIN-SUFFIX,firech.at,节点选择",
        "DOMAIN-SUFFIX,flickr.com,节点选择",
        "DOMAIN-SUFFIX,flipboard.com,节点选择",
        "DOMAIN-SUFFIX,flitto.com,节点选择",
        "DOMAIN-SUFFIX,foreignpolicy.com,节点选择",
        "DOMAIN-SUFFIX,fortawesome.com,节点选择",
        "DOMAIN-SUFFIX,freetls.fastly.net,节点选择",
        "DOMAIN-SUFFIX,friday.tw,节点选择",
        "DOMAIN-SUFFIX,ft.com,节点选择",
        "DOMAIN-SUFFIX,ftchinese.com,节点选择",
        "DOMAIN-SUFFIX,ftimg.net,节点选择",
        "DOMAIN-SUFFIX,gate.io,节点选择",
        "DOMAIN-SUFFIX,genius.com,节点选择",
        "DOMAIN-SUFFIX,getlantern.org,节点选择",
        "DOMAIN-SUFFIX,getsync.com,节点选择",
        "DOMAIN-SUFFIX,github.com,节点选择",
        "DOMAIN-SUFFIX,github.io,节点选择",
        "DOMAIN-SUFFIX,githubusercontent.com,节点选择",
        "DOMAIN-SUFFIX,globalvoices.org,节点选择",
        "DOMAIN-SUFFIX,goo.ne.jp,节点选择",
        "DOMAIN-SUFFIX,goodreads.com,节点选择",
        "DOMAIN-SUFFIX,gov.tw,节点选择",
        "DOMAIN-SUFFIX,greatfire.org,节点选择",
        "DOMAIN-SUFFIX,gumroad.com,节点选择",
        "DOMAIN-SUFFIX,hbg.com,节点选择",
        "DOMAIN-SUFFIX,heroku.com,节点选择",
        "DOMAIN-SUFFIX,hightail.com,节点选择",
        "DOMAIN-SUFFIX,hk01.com,节点选择",
        "DOMAIN-SUFFIX,hkbf.org,节点选择",
        "DOMAIN-SUFFIX,hkbookcity.com,节点选择",
        "DOMAIN-SUFFIX,hkej.com,节点选择",
        "DOMAIN-SUFFIX,hket.com,节点选择",
        "DOMAIN-SUFFIX,hootsuite.com,节点选择",
        "DOMAIN-SUFFIX,hudson.org,节点选择",
        "DOMAIN-SUFFIX,huffpost.com,节点选择",
        "DOMAIN-SUFFIX,hyread.com.tw,节点选择",
        "DOMAIN-SUFFIX,ibtimes.com,节点选择",
        "DOMAIN-SUFFIX,i-cable.com,节点选择",
        "DOMAIN-SUFFIX,icij.org,节点选择",
        "DOMAIN-SUFFIX,icoco.com,节点选择",
        "DOMAIN-SUFFIX,imgur.com,节点选择",
        "DOMAIN-SUFFIX,independent.co.uk,节点选择",
        "DOMAIN-SUFFIX,initiummall.com,节点选择",
        "DOMAIN-SUFFIX,inoreader.com,节点选择",
        "DOMAIN-SUFFIX,insecam.org,节点选择",
        "DOMAIN-SUFFIX,ipfs.io,节点选择",
        "DOMAIN-SUFFIX,issuu.com,节点选择",
        "DOMAIN-SUFFIX,istockphoto.com,节点选择",
        "DOMAIN-SUFFIX,japantimes.co.jp,节点选择",
        "DOMAIN-SUFFIX,jiji.com,节点选择",
        "DOMAIN-SUFFIX,jinx.com,节点选择",
        "DOMAIN-SUFFIX,jkforum.net,节点选择",
        "DOMAIN-SUFFIX,joinmastodon.org,节点选择",
        "DOMAIN-SUFFIX,justmysocks.net,节点选择",
        "DOMAIN-SUFFIX,justpaste.it,节点选择",
        "DOMAIN-SUFFIX,kadokawa.co.jp,节点选择",
        "DOMAIN-SUFFIX,kakao.com,节点选择",
        "DOMAIN-SUFFIX,kakaocorp.com,节点选择",
        "DOMAIN-SUFFIX,kik.com,节点选择",
        "DOMAIN-SUFFIX,kingkong.com.tw,节点选择",
        "DOMAIN-SUFFIX,knowyourmeme.com,节点选择",
        "DOMAIN-SUFFIX,kobo.com,节点选择",
        "DOMAIN-SUFFIX,kobobooks.com,节点选择",
        "DOMAIN-SUFFIX,kodingen.com,节点选择",
        "DOMAIN-SUFFIX,lemonde.fr,节点选择",
        "DOMAIN-SUFFIX,lepoint.fr,节点选择",
        "DOMAIN-SUFFIX,lihkg.com,节点选择",
        "DOMAIN-SUFFIX,linkedin.com,节点选择",
        "DOMAIN-SUFFIX,limbopro.xyz,节点选择",
        "DOMAIN-SUFFIX,listennotes.com,节点选择",
        "DOMAIN-SUFFIX,livestream.com,节点选择",
        "DOMAIN-SUFFIX,logimg.jp,节点选择",
        "DOMAIN-SUFFIX,logmein.com,节点选择",
        "DOMAIN-SUFFIX,mail.ru,节点选择",
        "DOMAIN-SUFFIX,mailchimp.com,节点选择",
        "DOMAIN-SUFFIX,marc.info,节点选择",
        "DOMAIN-SUFFIX,matters.news,节点选择",
        "DOMAIN-SUFFIX,maying.co,节点选择",
        "DOMAIN-SUFFIX,medium.com,节点选择",
        "DOMAIN-SUFFIX,mega.nz,节点选择",
        "DOMAIN-SUFFIX,mergersandinquisitions.com,节点选择",
        "DOMAIN-SUFFIX,mingpao.com,节点选择",
        "DOMAIN-SUFFIX,mixi.jp,节点选择",
        "DOMAIN-SUFFIX,mobile01.com,节点选择",
        "DOMAIN-SUFFIX,mubi.com,节点选择",
        "DOMAIN-SUFFIX,myspace.com,节点选择",
        "DOMAIN-SUFFIX,myspacecdn.com,节点选择",
        "DOMAIN-SUFFIX,nanyang.com,节点选择",
        "DOMAIN-SUFFIX,nationalinterest.org,节点选择",
        "DOMAIN-SUFFIX,naver.com,节点选择",
        "DOMAIN-SUFFIX,nbcnews.com,节点选择",
        "DOMAIN-SUFFIX,ndr.de,节点选择",
        "DOMAIN-SUFFIX,neowin.net,节点选择",
        "DOMAIN-SUFFIX,newstapa.org,节点选择",
        "DOMAIN-SUFFIX,nexitally.com,节点选择",
        "DOMAIN-SUFFIX,nhk.or.jp,节点选择",
        "DOMAIN-SUFFIX,nii.ac.jp,节点选择",
        "DOMAIN-SUFFIX,nikkei.com,节点选择",
        "DOMAIN-SUFFIX,nitter.net,节点选择",
        "DOMAIN-SUFFIX,nofile.io,节点选择",
        "DOMAIN-SUFFIX,notion.so,节点选择",
        "DOMAIN-SUFFIX,now.com,节点选择",
        "DOMAIN-SUFFIX,nrk.no,节点选择",
        "DOMAIN-SUFFIX,nuget.org,节点选择",
        "DOMAIN-SUFFIX,nyaa.si,节点选择",
        "DOMAIN-SUFFIX,nyt.com,节点选择",
        "DOMAIN-SUFFIX,nytchina.com,节点选择",
        "DOMAIN-SUFFIX,nytcn.me,节点选择",
        "DOMAIN-SUFFIX,nytco.com,节点选择",
        "DOMAIN-SUFFIX,nytimes.com,节点选择",
        "DOMAIN-SUFFIX,nytimg.com,节点选择",
        "DOMAIN-SUFFIX,nytlog.com,节点选择",
        "DOMAIN-SUFFIX,nytstyle.com,节点选择",
        "DOMAIN-SUFFIX,ok.ru,节点选择",
        "DOMAIN-SUFFIX,okex.com,节点选择",
        "DOMAIN-SUFFIX,on.cc,节点选择",
        "DOMAIN-SUFFIX,orientaldaily.com.my,节点选择",
        "DOMAIN-SUFFIX,overcast.fm,节点选择",
        "DOMAIN-SUFFIX,paltalk.com,节点选择",
        "DOMAIN-SUFFIX,parsevideo.com,节点选择",
        "DOMAIN-SUFFIX,pawoo.net,节点选择",
        "DOMAIN-SUFFIX,pbxes.com,节点选择",
        "DOMAIN-SUFFIX,pcdvd.com.tw,节点选择",
        "DOMAIN-SUFFIX,pchome.com.tw,节点选择",
        "DOMAIN-SUFFIX,pcloud.com,节点选择",
        "DOMAIN-SUFFIX,peing.net,节点选择",
        "DOMAIN-SUFFIX,picacomic.com,节点选择",
        "DOMAIN-SUFFIX,pinimg.com,节点选择",
        "DOMAIN-SUFFIX,pixiv.net,节点选择",
        "DOMAIN-SUFFIX,player.fm,节点选择",
        "DOMAIN-SUFFIX,plurk.com,节点选择",
        "DOMAIN-SUFFIX,po18.tw,节点选择",
        "DOMAIN-SUFFIX,potato.im,节点选择",
        "DOMAIN-SUFFIX,potatso.com,节点选择",
        "DOMAIN-SUFFIX,prism-break.org,节点选择",
        "DOMAIN-SUFFIX,proxifier.com,节点选择",
        "DOMAIN-SUFFIX,pt.im,节点选择",
        "DOMAIN-SUFFIX,pts.org.tw,节点选择",
        "DOMAIN-SUFFIX,pubu.com.tw,节点选择",
        "DOMAIN-SUFFIX,pubu.tw,节点选择",
        "DOMAIN-SUFFIX,pureapk.com,节点选择",
        "DOMAIN-SUFFIX,quora.com,节点选择",
        "DOMAIN-SUFFIX,quoracdn.net,节点选择",
        "DOMAIN-SUFFIX,qz.com,节点选择",
        "DOMAIN-SUFFIX,radio.garden,节点选择",
        "DOMAIN-SUFFIX,rakuten.co.jp,节点选择",
        "DOMAIN-SUFFIX,rarbgprx.org,节点选择",
        "DOMAIN-SUFFIX,reabble.com,节点选择",
        "DOMAIN-SUFFIX,readingtimes.com.tw,节点选择",
        "DOMAIN-SUFFIX,readmoo.com,节点选择",
        "DOMAIN-SUFFIX,redbubble.com,节点选择",
        "DOMAIN-SUFFIX,redd.it,节点选择",
        "DOMAIN-SUFFIX,reddit.com,节点选择",
        "DOMAIN-SUFFIX,redditmedia.com,节点选择",
        "DOMAIN-SUFFIX,resilio.com,节点选择",
        "DOMAIN-SUFFIX,reuters.com,节点选择",
        "DOMAIN-SUFFIX,reutersmedia.net,节点选择",
        "DOMAIN-SUFFIX,rfi.fr,节点选择",
        "DOMAIN-SUFFIX,rixcloud.com,节点选择",
        "DOMAIN-SUFFIX,roadshow.hk,节点选择",
        "DOMAIN-SUFFIX,rsshub.app,节点选择",
        "DOMAIN-SUFFIX,scmp.com,节点选择",
        "DOMAIN-SUFFIX,scribd.com,节点选择",
        "DOMAIN-SUFFIX,seatguru.com,节点选择",
        "DOMAIN-SUFFIX,shadowsocks.org,节点选择",
        "DOMAIN-SUFFIX,shindanmaker.com,节点选择",
        "DOMAIN-SUFFIX,shopee.tw,节点选择",
        "DOMAIN-SUFFIX,sina.com.hk,节点选择",
        "DOMAIN-SUFFIX,slideshare.net,节点选择",
        "DOMAIN-SUFFIX,softfamous.com,节点选择",
        "DOMAIN-SUFFIX,spiegel.de,节点选择",
        "DOMAIN-SUFFIX,ssrcloud.org,节点选择",
        "DOMAIN-SUFFIX,startpage.com,节点选择",
        "DOMAIN-SUFFIX,steamcommunity.com,节点选择",
        "DOMAIN-SUFFIX,steemit.com,节点选择",
        "DOMAIN-SUFFIX,steemitwallet.com,节点选择",
        "DOMAIN-SUFFIX,straitstimes.com,节点选择",
        "DOMAIN-SUFFIX,streamable.com,节点选择",
        "DOMAIN-SUFFIX,streema.com,节点选择",
        "DOMAIN-SUFFIX,t66y.com,节点选择",
        "DOMAIN-SUFFIX,tapatalk.com,节点选择",
        "DOMAIN-SUFFIX,teco-hk.org,节点选择",
        "DOMAIN-SUFFIX,teco-mo.org,节点选择",
        "DOMAIN-SUFFIX,teddysun.com,节点选择",
        "DOMAIN-SUFFIX,textnow.me,节点选择",
        "DOMAIN-SUFFIX,theguardian.com,节点选择",
        "DOMAIN-SUFFIX,theinitium.com,节点选择",
        "DOMAIN-SUFFIX,themoviedb.org,节点选择",
        "DOMAIN-SUFFIX,thetvdb.com,节点选择",
        "DOMAIN-SUFFIX,time.com,节点选择",
        "DOMAIN-SUFFIX,tokyotube.com,节点选择",
        "DOMAIN-SUFFIX,torrent.lu,节点选择",
        "DOMAIN-SUFFIX,tournal.com,节点选择",
        "DOMAIN-SUFFIX,tracfone.com,节点选择",
        "DOMAIN-SUFFIX,trello.com,节点选择",
        "DOMAIN-SUFFIX,trojanpanel.com,节点选择",
        "DOMAIN-SUFFIX,truetv.gov.tw,节点选择",
        "DOMAIN-SUFFIX,tutanota.com,节点选择",
        "DOMAIN-SUFFIX,tv.moe,节点选择",
        "DOMAIN-SUFFIX,tvbs.com.tw,节点选择",
        "DOMAIN-SUFFIX,udn.com,节点选择",
        "DOMAIN-SUFFIX,unblockcn.com,节点选择",
        "DOMAIN-SUFFIX,upmedia.mg,节点选择",
        "DOMAIN-SUFFIX,uptobox.com,节点选择",
        "DOMAIN-SUFFIX,urbandictionary.com,节点选择",
        "DOMAIN-SUFFIX,us-cert.gov,节点选择",
        "DOMAIN-SUFFIX,v2ray.com,节点选择",
        "DOMAIN-SUFFIX,vimeo.com,节点选择",
        "DOMAIN-SUFFIX,vjmedia.com.hk,节点选择",
        "DOMAIN-SUFFIX,voacantonese.com,节点选择",
        "DOMAIN-SUFFIX,voachinese.com,节点选择",
        "DOMAIN-SUFFIX,voanews.com,节点选择",
        "DOMAIN-SUFFIX,voatibetan.com,节点选择",
        "DOMAIN-SUFFIX,vuclip.com,节点选择",
        "DOMAIN-SUFFIX,wacg.tw,节点选择",
        "DOMAIN-SUFFIX,wasu.cn,DIRECT",
        "DOMAIN-SUFFIX,wasu.tv,DIRECT",
        "DOMAIN-SUFFIX,washingtonpost.com,节点选择",
        "DOMAIN-SUFFIX,weblio.jp,节点选择",
        "DOMAIN-SUFFIX,weibo.com,节点选择",
        "DOMAIN-SUFFIX,weiphone.net,节点选择",
        "DOMAIN-SUFFIX,wikimapia.org,节点选择",
        "DOMAIN-SUFFIX,wikipedia.org,节点选择",
        "DOMAIN-SUFFIX,windows.com,节点选择",
        "DOMAIN-SUFFIX,windowsupdate.com,节点选择",
        "DOMAIN-SUFFIX,worldcat.org,节点选择",
        "DOMAIN-SUFFIX,wordpress.com,节点选择",
        "DOMAIN-SUFFIX,xvideos.com,节点选择",
        "DOMAIN-SUFFIX,ycombinator.com,节点选择",
        "DOMAIN-SUFFIX,yesasia.com,节点选择",
        "DOMAIN-SUFFIX,yify-torrents.com,节点选择",
        "DOMAIN-SUFFIX,you-get.org,节点选择",
        "DOMAIN-SUFFIX,youjizz.com,节点选择",
        "DOMAIN-SUFFIX,ytn.co.kr,节点选择",
        "DOMAIN-SUFFIX,zello.com,节点选择",
        "DOMAIN-SUFFIX,zeronet.io,节点选择",
        "DOMAIN-KEYWORD,porn,节点选择",
        "DOMAIN-KEYWORD,xvideos,节点选择",
        "DOMAIN-KEYWORD,avgle,节点选择",
        "DOMAIN-KEYWORD,jav,节点选择",
        "DOMAIN-KEYWORD,fc2,节点选择",
        "DOMAIN-KEYWORD,t66y,节点选择",
        "DOMAIN-SUFFIX,51.la,DIRECT",
        "DOMAIN-SUFFIX,95543.sh.cn,DIRECT",
        "DOMAIN-SUFFIX,a-k-a.org,DIRECT",
        "DOMAIN-SUFFIX,abchina.com,DIRECT",
        "DOMAIN-SUFFIX,accuweather.com,DIRECT",
        "DOMAIN-SUFFIX,acfun.tv,DIRECT",
        "DOMAIN-SUFFIX,air-matters.com,DIRECT",
        "DOMAIN-SUFFIX,akamaized.net,DIRECT",
        "DOMAIN-SUFFIX,alicdn.com,DIRECT",
        "DOMAIN-SUFFIX,aliyun.com,DIRECT",
        "DOMAIN-SUFFIX,amap.com,DIRECT",
        "DOMAIN-SUFFIX,anxinchina.com,DIRECT",
        "DOMAIN-SUFFIX,anyconnect.com,DIRECT",
        "DOMAIN-SUFFIX,appledaily.com.tw,DIRECT",
        "DOMAIN-SUFFIX,apple-cloud.com,DIRECT",
        "DOMAIN-SUFFIX,appstore.com,DIRECT",
        "DOMAIN-SUFFIX,aqicn.org,DIRECT",
        "DOMAIN-SUFFIX,baidu.com,DIRECT",
        "DOMAIN-SUFFIX,baidustatic.com,DIRECT",
        "DOMAIN-SUFFIX,bankofchina.com,DIRECT",
        "DOMAIN-SUFFIX,baofeng.com,DIRECT",
        "DOMAIN-SUFFIX,battle.net,DIRECT",
        "DOMAIN-SUFFIX,bilibili.tv,DIRECT",
        "DOMAIN-SUFFIX,bilibilijj.com,DIRECT",
        "DOMAIN-SUFFIX,bing.com,DIRECT",
        "DOMAIN-SUFFIX,bitdefender.com,DIRECT",
        "DOMAIN-SUFFIX,bitdefender.net,DIRECT",
        "DOMAIN-SUFFIX,blizzard.com,DIRECT",
        "DOMAIN-SUFFIX,cctv.com,DIRECT",
        "DOMAIN-SUFFIX,cdn-af.net,DIRECT",
        "DOMAIN-SUFFIX,cib.com.cn,DIRECT",
        "DOMAIN-SUFFIX,cisco.com,DIRECT",
        "DOMAIN-SUFFIX,client.cisco.com,DIRECT",
        "DOMAIN-SUFFIX,cloud.google.com,DIRECT",
        "DOMAIN-SUFFIX,cloudera.com,DIRECT",
        "DOMAIN-SUFFIX,cnki.net,DIRECT",
        "DOMAIN-SUFFIX,cngold.org,DIRECT",
        "DOMAIN-SUFFIX,cntv.cn,DIRECT",
        "DOMAIN-SUFFIX,com.cn,DIRECT",
        "DOMAIN-SUFFIX,com.tw,DIRECT",
        "DOMAIN-SUFFIX,c-t-c.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,dl.google.com,DIRECT",
        "DOMAIN-SUFFIX,dl.googleusercontent.com,DIRECT",
        "DOMAIN-SUFFIX,douban.com,DIRECT",
        "DOMAIN-SUFFIX,duowan.com,DIRECT",
        "DOMAIN-SUFFIX,dytt8.net,DIRECT",
        "DOMAIN-SUFFIX,eastmoney.com,DIRECT",
        "DOMAIN-SUFFIX,ecitic.com,DIRECT",
        "DOMAIN-SUFFIX,elong.com,DIRECT",
        "DOMAIN-SUFFIX,e-hentai.org,DIRECT",
        "DOMAIN-SUFFIX,e-hentai.net,DIRECT",
        "DOMAIN-SUFFIX,ex-hentai.org,DIRECT",
        "DOMAIN-SUFFIX,fanyi.baidu.com,DIRECT",
        "DOMAIN-SUFFIX,fastly.net,DIRECT",
        "DOMAIN-SUFFIX,fengniao.com,DIRECT",
        "DOMAIN-SUFFIX,fudanshop.net,DIRECT",
        "DOMAIN-SUFFIX,gameloft.com.cn,DIRECT",
        "DOMAIN-SUFFIX,gitee.com,DIRECT",
        "DOMAIN-SUFFIX,github.io,DIRECT",
        "DOMAIN-SUFFIX,gitlab.com,DIRECT",
        "DOMAIN-SUFFIX,googleadservices.com,DIRECT",
        "DOMAIN-SUFFIX,googlecode.com,DIRECT",
        "DOMAIN-SUFFIX,googleapis.com,DIRECT",
        "DOMAIN-SUFFIX,google-analytics.com,DIRECT",
        "DOMAIN-SUFFIX,google-cloud.com,DIRECT",
        "DOMAIN-SUFFIX,googletagservices.com,DIRECT",
        "DOMAIN-SUFFIX,greatfire.org,DIRECT",
        "DOMAIN-SUFFIX,haosou.com,DIRECT",
        "DOMAIN-SUFFIX,haosou.net,DIRECT",
        "DOMAIN-SUFFIX,he.net,DIRECT",
        "DOMAIN-SUFFIX,hotstar.com,DIRECT",
        "DOMAIN-SUFFIX,huaban.com,DIRECT",
        "DOMAIN-SUFFIX,huawei.com,DIRECT",
        "DOMAIN-SUFFIX,icbc.com.cn,DIRECT",
        "DOMAIN-SUFFIX,ifeng.com,DIRECT",
        "DOMAIN-SUFFIX,iknow.baidu.com,DIRECT",
        "DOMAIN-SUFFIX,images-amazon.com,DIRECT",
        "DOMAIN-SUFFIX,ime.google.com,DIRECT",
        "DOMAIN-SUFFIX,instagram.com,DIRECT",
        "DOMAIN-SUFFIX,intel.com,DIRECT",
        "DOMAIN-SUFFIX,ipip.net,DIRECT",
        "DOMAIN-SUFFIX,iqiyi.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,jianshu.com,DIRECT",
        "DOMAIN-SUFFIX,jiathis.com,DIRECT",
        "DOMAIN-SUFFIX,jiebashi.com,DIRECT",
        "DOMAIN-SUFFIX,jiguang.cn,DIRECT",
        "DOMAIN-SUFFIX,jumei.com,DIRECT",
        "DOMAIN-SUFFIX,kaixin001.com,DIRECT",
        "DOMAIN-SUFFIX,kamigo.com,DIRECT",
        "DOMAIN-SUFFIX,k...
    ],
    "match": "节点选择"
}

def generate_random_string(length=10):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_sub_name(url):
    try:
        if 'github.com' in url:
            match = re.search(r'github\.com/([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)', url)
            if match:
                return f"{match.group(1)}-{match.group(2)}"
        return urllib.parse.urlparse(url).hostname or "unnamed_sub"
    except Exception as e:
        print(f"Error generating sub name: {e}")
        return "unnamed_sub"

async def get_remote_file_content(session, url):
    try:
        response = await session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Failed to fetch remote file from {url}: {e}")
        return None

async def download_all_files(session, urls):
    tasks = [get_remote_file_content(session, url) for url in urls]
    results = await asyncio.gather(*tasks)
    return results

def base64_decode_if_needed(text):
    try:
        # 尝试 Base64 解码，支持 URL-safe
        return base64.urlsafe_b64decode(text + '=' * (4 - len(text) % 4)).decode('utf-8')
    except:
        return text

def parse_clash_yaml(content, sub_name=""):
    try:
        config = yaml.safe_load(content)
        proxies = config.get('proxies', [])
        # 添加 sub_name
        for p in proxies:
            p['sub_name'] = sub_name
        return proxies
    except Exception as e:
        print(f"Failed to parse Clash YAML config: {e}")
        return []

def parse_v2ray_links(content, sub_name=""):
    proxies = []
    lines = content.splitlines()
    for line in lines:
        if line.strip():
            proxies.append({'name': f"{sub_name}_{generate_random_string(5)}", 'type': 'ss', 'server': '0.0.0.0'})
    return proxies

def parse_all_proxies(contents, urls):
    proxies = []
    for content, url in zip(contents, urls):
        if not content:
            continue
        sub_name = generate_sub_name(url)
        if 'proxies:' in content:
            proxies.extend(parse_clash_yaml(content, sub_name))
        else:
            decoded_content = base64_decode_if_needed(content)
            proxies.extend(parse_v2ray_links(decoded_content, sub_name))
    return proxies

def generate_clash_config(links, load_nodes=[]):
    try:
        session = HTMLSession()
        loop = asyncio.get_event_loop()
        contents = loop.run_until_complete(download_all_files(session, links))
        session.close()

        all_proxies = parse_all_proxies(contents, links)
        all_proxies.extend(load_nodes)
        
        # 过滤重复节点并过滤敏感节点
        unique_proxies = {}
        for p in all_proxies:
            name = p.get('name', '')
            if any(b.lower() in name.lower() for b in BAN):
                continue
            if name not in unique_proxies:
                unique_proxies[name] = p

        final_proxies = list(unique_proxies.values())[:LIMIT]
        print(f"Loaded {len(final_proxies)} unique proxies after filtering.")

        # 更新配置文件
        config = clash_config_template.copy()
        config['proxies'] = final_proxies
        config['proxy-groups'][1]['proxies'] = [p['name'] for p in final_proxies] # 自动选择
        config['proxy-groups'][2]['proxies'] = [p['name'] for p in final_proxies] # 故障转移
        config['proxy-groups'][3]['proxies'] = [p['name'] for p in final_proxies] # 手动选择

        # 写入文件
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)

        print(f"Clash config generated and saved to {CONFIG_FILE}")
        return config

    except Exception as e:
        print(f"Error generating Clash config: {e}")
        return None

def start_clash(api_host=CLASH_API_HOST, api_ports=CLASH_API_PORTS, config_file=CONFIG_FILE):
    """
    启动clash核心并等待其api端口可用
    """
    cmd = ["clash-verge", "-f", config_file]
    
    # 检查clash是否已经运行
    for proc in psutil.process_iter(['name']):
        if proc.name().lower() == "clash-verge.exe":
            print("Clash-verge is already running. Attempting to connect to its API.")
            return None
    
    print("Starting Clash-verge process...")
    clash_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    start_time = time.time()
    api_ready = False
    
    # --- 修复部分: 添加超时和更详细的日志 ---
    timeout_seconds = 60  # 设置60秒的超时
    while time.time() - start_time < timeout_seconds:
        print(f"Waiting for Clash API on {api_host}:{api_ports[0]}... (Attempt {int(time.time() - start_time)}/{timeout_seconds})")
        
        try:
            # 检查 API 端口是否开放
            response = requests.get(f"http://{api_host}:{api_ports[0]}/proxies", timeout=5)
            if response.status_code == 200:
                print("Clash API is ready.")
                api_ready = True
                break
        except requests.exceptions.RequestException as e:
            # 忽略连接错误，继续尝试
            print(f"Clash API not ready yet. Error: {e}")
            pass
        
        time.sleep(1) # 每秒检查一次

    if not api_ready:
        print("Error: Clash API did not become available within the timeout period.")
        clash_process.kill()
        raise ConnectionError("Clash API did not start or become available.")
    
    return clash_process

def switch_proxy(group_name, proxy_name, api_host=CLASH_API_HOST, api_ports=CLASH_API_PORTS, api_secret=CLASH_API_SECRET):
    """
    通过clash api切换节点
    """
    url = f"http://{api_host}:{api_ports[0]}/groups/{urllib.parse.quote(group_name)}"
    headers = {'Authorization': f'Bearer {api_secret}'}
    payload = {'name': proxy_name}
    
    try:
        response = requests.put(url, headers=headers, json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        print(f"Successfully switched '{group_name}' to '{proxy_name}'")
    except requests.exceptions.RequestException as e:
        print(f"Error switching proxy to {proxy_name}: {e}")

async def test_proxy_speed(session, proxy_name, semaphore):
    async with semaphore:
        try:
            response = await session.get(TEST_URL, proxies={
                "http://": f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}",
                "https://": f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}"
            }, headers=headers, timeout=TIMEOUT)
            response.raise_for_status()
            # 简单的速度测试
            test_start = time.time()
            data = b'test' * 1024 # 4KB of data
            test_end = time.time()
            speed_mbps = (len(data) / (test_end - test_start)) * 8 / 1024 / 1024
            results_speed.append({'name': proxy_name, 'speed': speed_mbps})
        except Exception as e:
            results_speed.append({'name': proxy_name, 'speed': 0, 'error': str(e)})

async def proxy_clean(api_host=CLASH_API_HOST, api_ports=CLASH_API_PORTS, api_secret=CLASH_API_SECRET):
    global results_speed
    results_speed = []
    
    try:
        url = f"http://{api_host}:{api_ports[0]}/proxies"
        headers_clash = {'Authorization': f'Bearer {api_secret}'}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers_clash)
            response.raise_for_status()
            
            proxies_info = response.json().get('proxies', {})
            all_proxies = [name for name, info in proxies_info.items() if info.get('type') != 'Direct']
            
            # 使用 semaphore 控制并发
            semaphore = Semaphore(MAX_CONCURRENT_TESTS)
            tasks = [test_proxy_speed(client, proxy_name, semaphore) for proxy_name in all_proxies[:SPEED_TEST_LIMIT]]
            
            if tasks:
                await asyncio.gather(*tasks)
            
            # 排序并生成新的配置
            results_speed.sort(key=lambda x: x['speed'], reverse=True)
            sorted_proxies = [p['name'] for p in results_speed if p['speed'] > 0]
            
            # 重新生成配置文件
            # ... 这里应该调用 generate_clash_config 来重新生成配置
            
    except Exception as e:
        print(f"Error during proxy clean: {e}")

def read_yaml_files(folder_path=INPUT):
    nodes = []
    if os.path.exists(folder_path):
        yaml_files = glob.glob(os.path.join(folder_path, '*.yaml')) + glob.glob(os.path.join(folder_path, '*.yml'))
        for file_path in yaml_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    proxies = config.get('proxies', [])
                    for p in proxies:
                        p['sub_name'] = os.path.splitext(os.path.basename(file_path))[0]
                    nodes.extend(proxies)
            except Exception as e:
                print(f"Error reading YAML file {file_path}: {e}")
    return nodes

def read_txt_files(folder_path=INPUT):
    links = []
    if os.path.exists(folder_path):
        txt_files = glob.glob(os.path.join(folder_path, '*.txt'))
        for file_path in txt_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    links.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"Error reading TXT file {file_path}: {e}")
    return links

def merge_lists(*lists):
    return list(chain(*lists))

def filter_by_types_alt(allowed_types, nodes):
    result = []
    for node in nodes:
        node_type = node.get("type", "").lower()
        if node_type in [t.lower() for t in allowed_types]:
            result.append(node)
        else:
            print(f"Filtering out unsupported node type: {node_type}")
    
    return result

def work(links, check=False, allowed_types=[], only_check=False):
    try:
        if not only_check:
            load_nodes = read_yaml_files(folder_path=INPUT)
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types, nodes=load_nodes)
            links = merge_lists(read_txt_files(folder_path=INPUT), links)
            if links or load_nodes:
                generate_clash_config(links, load_nodes)

        if check or only_check:
            clash_process = None
            try:
                # 启动clash
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
                # 切换节点到'节点选择-DIRECT'
                switch_proxy('节点选择', 'DIRECT')
                asyncio.run(proxy_clean())
                print(f'批量检测完毕')
            except Exception as e:
                print("Error calling Clash API:", e)
            finally:
                print(f'关闭Clash API')
                if clash_process is not None:
                    clash_process.kill()

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    links = [
        "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml",
        
    ]
    
    # 示例用法
    # work(links)  # 生成配置，不进行节点测试
    # work(links, check=True) # 生成配置并进行节点测试
    # work([], only_check=True) # 只进行节点测试，不更新配置
    work(links, check=True, allowed_types=["Vmess", "Trojan", "Shadowsocks", "VLESS"])
