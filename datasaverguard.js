'use strict';

// datasaverguard.js —— Save-Data 省流量模式决策内核。
//
// W3C NetInfo.saveData / 客户端“省流量”开关下，浏览器应该：
//
//   - 透传 `Save-Data: on` 请求头；
//   - 不自动加载大图/自动播放视频；
//   - 降级第三方字体/脚本。
//
// 这里把“当前这趟网络请求/资源加载该走什么档”收敛成纯函数，main/renderer 共用。

const TIER = {
  FULL: 'full', // 正常加载
  SAVE: 'save', // 省流量：降图、禁自动播放
  OFFLINE: 'offline', // 离线：只走缓存
};

// decideTier 入参：
//   saveDataOn 布尔（用户开关或 NavigatorConnection.saveData）
//   offline    布尔
//   allowOverride 布尔（用户本页是否临时开了“始终高清”）
function decideTier(saveDataOn, offline, allowOverride) {
  if (offline) return TIER.OFFLINE;
  if (saveDataOn && !allowOverride) return TIER.SAVE;
  return TIER.FULL;
}

// shouldAutoBlockMedia 在 SAVE/OFFLINE 下是否拦自动媒体。
function shouldAutoBlockMedia(tier, mediaKind) {
  if (tier === TIER.FULL) return false;
  const kind = String(mediaKind || '').toLowerCase();
  return kind === 'video' || kind === 'animated-gif';
}

// shouldDownscaleImage 在 SAVE 下是否把图降到缩略图档。
function shouldDownscaleImage(tier, imageBytes) {
  if (tier !== TIER.SAVE) return false;
  return Number(imageBytes || 0) > 300 * 1024;
}

// saveDataHeaderValue 返回要写进请求头的值（'' 表示不写）。
function saveDataHeaderValue(tier) {
  return tier === TIER.SAVE ? 'on' : '';
}

module.exports = {
  TIER,
  decideTier,
  shouldAutoBlockMedia,
  shouldDownscaleImage,
  saveDataHeaderValue,
};
