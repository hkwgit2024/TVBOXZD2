<?php

namespace Core;

class ConfigManager
{
    private static $instance = null;
    private $logger;
    private $config;
    private $configFile;
    private $httpManager;
    private $linkTypeSortKeys = null; // 缓存 link_type 排序键

    // 原始频道分组（不可变）
    private $originChannelGroup = [
        'CCTV48K',   // CCTV 4K/8K 频道
        '4K',        // 其他 4K 频道
        '8K',        // 其他 8K 频道
        'CCTV',      // CCTV 频道
        'CGTN',      // CGTN 频道
        '央视数字',   // 央视数字频道
        '卫视',      // 卫视频道
        '地方',      // 地方频道
        '教育',      // 教育频道
        '体育',      // 体育频道
        '求索',      // 求索频道
        'NewTV',     // NewTV 频道
        'iHOT',      // iHOT 频道
        'SiTV',      // SiTV 频道
        '咪视通',      // 咪视通
        '湖南bblive',  // 湖南bblive
        '易视腾',      // 易视腾
        '熊猫',      // 熊猫频道
        '其他'       // 其他频道
    ];

    // link_type 的 key 值
    private $linkTypeKey = [
        'mgtv',
        'nptv',
        'gaoma',
        'itv',
        'migu',
        'bptv',
        'slive',
        'gdcucc',
        'cloudfront',
        'other',
    ];

    // 默认配置
    private $defaultConfig = [
        'tv_m3u_url' => '',
        'reverse_proxy_domain' => '', // allinone_format 反向代理域名
        'fetch_migu' => true, // 是否抓取 migu.m3u
        'migu_uid' => '', // 咪咕 uid
        'migu_token' => '', // 咪咕 token
        'link_output_jump' => true, // 是否输出跳转链接
        'link_output_desc' => true, // 是否输出频道描述
        'link_type' => [
            'mgtv' => true,        // mgtv
            'nptv' => true,        // nptv
            'gaoma' => true,       // 高码频道
            'itv' => true,        // itv 频道
            'migu' => true,       // 咪咕频道
            'bptv' => true,       // bptv 频道
            'slive' => true,      // 直播频道
            'gdcucc' => true,     // 广电频道
            'cloudfront' => true, // CDN 频道
            'other' => true,      // 其他频道
        ],
        // 废弃的原始频道分组
        'deprecated_origin_channel_group' => [],
        // 输出频道分组
        'output_channel_group' => [
            '4 K 8 K' => ['CCTV48K', '4K', '8K'],
            '央视频道' => ['CCTV'],
            '卫视频道' => ['卫视'],
            '地方频道' => ['地方'],
            '数字频道' => ['CGTN', '央视数字', '教育', '体育', '求索', 'NewTV', 'iHOT', 'SiTV', '咪视通', '湖南bblive', '易视腾', '熊猫', '其他']
        ]
    ];

    private function __construct()
    {
        $this->logger = new LogManager();
        $this->httpManager = new HttpManager();
        $this->configFile = dirname(dirname(__DIR__)) . '/config/config.json';
        $this->loadConfig();
    }

    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 获取配置
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * 更新配置
     * @param array $newConfig
     * @return void
     */
    public function updateConfig($newConfig)
    {
        $errors = [];
        // 只验证提交的字段
        foreach ($newConfig as $field => $value) {
            if (!isset($this->defaultConfig[$field])) {
                $errors[] = "未知的配置项: {$field}";
                continue;
            }
            $result = $this->validateField($newConfig, $field, $this->defaultConfig[$field]);
            if ($result['error']) {
                $errors[] = $result['error'];
                continue;
            }
            // 更新配置
            $this->config[$field] = $result['value'];
            // 如果更新了 link_type，删除缓存排序键
            if ($field === 'link_type') {
                $this->linkTypeSortKeys = null;
            }
        }

        // 如果有错误，抛出所有错误信息
        if (!empty($errors)) {
            throw new \Exception(implode("\n", $errors));
        }

        // 如果更新了 tv_m3u_url，检查链接内容
        if (isset($newConfig['tv_m3u_url'])) {
            $content = $this->httpManager->fetchContent($newConfig['tv_m3u_url']);
            if ($content) {
                if (strpos($content, '#EXTM3U') === false) {
                    throw new \Exception('tv.m3u 地址返回内容不是 m3u 格式: ' . $newConfig['tv_m3u_url']);
                }
            } else {
                throw new \Exception('tv.m3u 地址无法访问: ' . $newConfig['tv_m3u_url']);
            }
        }

        $this->saveConfig();
    }

    /**
     * 获取 link_type 排序键
     * @return array
     */
    public function getLinkTypeSortKeys()
    {
        if ($this->linkTypeSortKeys === null) {
            $this->linkTypeSortKeys = array_keys($this->config['link_type']);
        }
        return $this->linkTypeSortKeys;
    }

    /**
     * 获取原始频道分组
     * @return array
     */
    public function getOriginChannelGroup()
    {
        return $this->originChannelGroup;
    }

    /**
     * 获取未分配的原始频道分组
     * @return array
     */
    public function getUnassignedOriginChannelGroup()
    {
        return array_diff($this->originChannelGroup, array_merge(...array_values($this->config['output_channel_group'])), $this->config['deprecated_origin_channel_group']);
    }

    /**
     * 验证配置字段
     * @param array $config
     * @param string $field
     * @param mixed $defaultValue
     * @return array
     */
    private function validateField($config, $field, $defaultValue)
    {
        $result = ['value' => $defaultValue, 'error' => null];
        // 如果缺少配置，使用默认值。这个逻辑是为了兼容后续新增配置项
        if (!isset($config[$field])) {
            $this->logger->warning("缺少 {$field} 配置, 使用默认值");
            return $result;
        }

        switch ($field) {
            case 'tv_m3u_url':
                if (empty($config[$field])) {
                    $result['error'] = "{$field} 订阅源必须设置";
                } elseif (!filter_var($config[$field], FILTER_VALIDATE_URL)) {
                    $result['error'] = "{$field} 请输入有效的 http/https 链接";
                } elseif (strpos($config[$field], ':35456') !== false) {
                    $result['error'] = "{$field} 不能使用本服务的端口(35456)";
                } else {
                    $result['value'] = $config[$field];
                }
                break;

            case 'reverse_proxy_domain':
                if (!empty($config[$field])) {
                    // 反向代理不为空的时候需要检查是否是域名格式 https?://域名[:端口][/path]
                    if (
                        !filter_var($config[$field], FILTER_VALIDATE_URL)
                        || filter_var($config[$field], FILTER_VALIDATE_URL, FILTER_FLAG_QUERY_REQUIRED)
                        || substr($config[$field], -1) === '/'
                    ) {
                        $result['error'] = "{$field} 请输入有效的 https?://域名[:端口][/path] 格式";
                    } else {
                        $result['value'] = $config[$field];
                    }
                }
                break;

            case 'link_output_jump':
            case 'link_output_desc':
                if (!is_bool($config[$field])) {
                    $result['error'] = "{$field} 配置格式错误";
                } else {
                    $result['value'] = $config[$field];
                }
                break;

            case 'link_type':
                if (!is_array($config[$field])) {
                    $result['error'] = "{$field} 配置格式错误";
                } else {
                    // 删除未识别的 key
                    foreach (array_keys($config[$field]) as $key) {
                        if (!in_array($key, $this->linkTypeKey)) {
                            unset($config[$field][$key]);
                        }
                    }
                    // 添加缺失的 key
                    foreach ($this->linkTypeKey as $key) {
                        if (!isset($config[$field][$key])) {
                            $config[$field][$key] = $defaultValue[$key];
                        }
                    }
                    // 检查是否至少启用一种直播源类型
                    $enabledTypes = array_filter($config[$field]);
                    if (empty($enabledTypes)) {
                        $result['error'] = "{$field} 至少需要启用一种直播源类型";
                    } else {
                        $result['value'] = $config[$field];
                    }
                }
                break;

            case 'output_channel_group':
                if (!is_array($config[$field])) {
                    $result['error'] = "{$field} 配置格式错误";
                } elseif (empty($config[$field])) {
                    $result['error'] = "{$field} 至少需要创建一个分组";
                } else {
                    $groupNames = array_keys($config[$field]);
                    if (count(array_unique($groupNames)) !== count($groupNames)) {
                        $result['error'] = "{$field} 分组名称不能重复";
                    } else {
                        foreach ($config[$field] as $groupName => $channels) {
                            // 如果是对象格式，转换为数组
                            if (is_object($channels) || (is_array($channels) && array_keys($channels) !== range(0, count($channels) - 1))) {
                                $channels = array_values((array)$channels);
                                $config[$field][$groupName] = $channels;
                            }

                            // 删除分组中不是原始频道分类的频道
                            foreach ($channels as $idx => $channel) {
                                if (!in_array($channel, $this->originChannelGroup)) {
                                    unset($config[$field][$groupName][$idx]);
                                    continue;
                                }
                            }
                            // 重新索引数组，确保是连续的数字索引
                            $config[$field][$groupName] = array_values($config[$field][$groupName]);

                            // 分组下一个原始频道分类都没有就删除这个分组
                            if (empty($config[$field][$groupName])) {
                                unset($config[$field][$groupName]);
                            }
                        }
                        if (empty($config[$field])) {
                            $result['error'] = "{$field} 至少需要创建一个分组";
                        } else {
                            $result['value'] = $config[$field];
                        }
                    }
                }
                break;

            default:
                $result['value'] = $config[$field];
        }

        return $result;
    }

    /**
     * 加载配置从 config.json
     * @return void
     */
    private function loadConfig()
    {
        if (file_exists($this->configFile)) {
            $content = @file_get_contents($this->configFile);
            if ($content === false) {
                @unlink($this->configFile);
                $this->logger->error('无法读取 config.json 配置文件');
                $this->config = $this->defaultConfig;
                return;
            }

            $config = json_decode($content, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                @unlink($this->configFile);
                $this->logger->error('config.json 配置文件格式错误: ' . json_last_error_msg());
                $this->config = $this->defaultConfig;
                return;
            }

            $validatedConfig = [];
            foreach ($this->defaultConfig as $field => $defaultValue) {
                $result = $this->validateField($config, $field, $defaultValue);
                if ($result['error']) {
                    $this->logger->error($result['error']);
                }
                $validatedConfig[$field] = $result['value'];
            }

            $this->config = $validatedConfig;
        } else {
            $this->config = $this->defaultConfig;
        }
    }

    /**
     * 保存配置到 config.json
     * @return void
     */
    private function saveConfig()
    {
        $configDir = dirname($this->configFile);

        if (!is_dir($configDir)) {
            if (!mkdir($configDir, 0755, true)) {
                throw new \Exception('无法创建配置目录');
            }
        }

        if (file_put_contents($this->configFile, json_encode($this->config, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) === false) {
            throw new \Exception('无法保存配置文件');
        }
    }
}
