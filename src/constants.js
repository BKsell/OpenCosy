// OpenCosy浏览器常量定义文件
// 用于存储软件的基本信息和配置常量

/**
 * 软件基本信息
 */
const APP_INFO = {
    name: 'OpenCosy浏览器',

    description: 'OpenCosy浏览器 - 基于Electron的多标签页浏览器',

    version: '1.0.0',

    versionType: 'stable',

    fullVersion: 'v1.0.0',

    author: 'OpenCosy',

    copyright: '© 2026 热土工作室 | Licensed under Apache 2.0',

    website: '',

    homepage: 'cosy://newtab',

    settingsUrl: 'cosy://setting',

    extensionsUrl: 'cosy://extensions',

    versionUrl: 'cosy://version'
};

/**
 * 软件配置常量
 */
const APP_CONFIG = {
    defaultTab: 'newtab',

    defaultSearchEngine: 'bing',

    enableExtensions: true,

    enableRandomBackground: true,

    backgroundApi: '',

    apiDocumentation: ''
};

/**
 * 导出常量对象
 */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        APP_INFO,
        APP_CONFIG
    };
} else {
    window.COSY_CONSTANTS = {
        APP_INFO,
        APP_CONFIG
    };
}