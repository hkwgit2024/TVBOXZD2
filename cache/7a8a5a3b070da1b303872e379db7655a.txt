package tvbox.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import tvbox.config.Constant;
import tvbox.pojo.M3U8;

import java.util.ArrayList;
import java.util.List;

import static tvbox.config.Constant.EXTINF;

@Slf4j
public class Utils {

    public M3U8 from (String first, String url) {
        M3U8 m3u8 = new M3U8();
        return m3u8;
    }

    public List<String> to (M3U8 m3u8) {
        List<String> list = new ArrayList<>(2);
        return list;
    }

    //#EXTM3U
    //#EXTINF:-1 group-title="偶像" tvg-logo="https://i2.100024.xyz/2023/09/11/11a5d62.webp",漂亮 上
    //https://fufxtyc.bytebwq.com/api/app/media/m3u8/av/ph/gr/7v/78/af7b145ecae246b2ac79cecb6f47f6ad.m3u8?
    public List<M3U8> from (List<String> list) {
        List<M3U8> result = new ArrayList<>();
        if (list == null || list.isEmpty()) {
            return result;
        }
        String markStr = list.get(0).trim();
        if (!"#EXTM3U".equals(markStr)) {
            log.error("解析失败，第一行标志位不是#EXTM3U");
            return result;
        }
        if (list.size()%2==0) {
            log.error("解析失败，除第一行标志位外，数据总行数为奇数，标签与url的匹配无法正确匹配");
        }
        for (int i = 1; i < list.size(); i=i+2) {
            String labels = list.get(i);
            String url = list.get(i + 1);
            if (labels.startsWith(EXTINF)) {

            }
        }
    }

    /**
     * @Description: 判断是否是为url链接
     */
    public static boolean isUrl(String str) {
        if (StringUtils.isEmpty(str)){
            return false;
        }
        str = str.trim();
        return str.matches("^(http|https)://.+");
    }
}