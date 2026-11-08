'use strict';

// dnsthemebypass.js —— 暗色/亮色主题跟随的反劫持守卫。
//
// 现代浏览器用 prefers-color-scheme 暴露系统主题。某些恶意站点会在
// <meta name="color-scheme"> 或 CSS 里强制覆盖，导致 UI 被反色、不可读。
// 这里把"是否允许页面覆盖 shell 的主题"收敛成纯函数策略。

// decideColorSchemeOverride 入参：
//   shellTheme       'dark' | 'light'
//   pageMetaScheme   页面 <meta name="color-scheme"> 解析出的列表，如 ['light','dark']
//   userTrustOrigin  布尔：用户在站点权限里允许过自定义主题
// 返回 { effective:'dark'|'light', allowPageOverride:boolean }
function decideColorSchemeOverride(opts) {
  const o = opts || {};
  const shell = o.shellTheme === 'dark' ? 'dark' : 'light';
  const page = Array.isArray(o.pageMetaScheme) ? o.pageMetaScheme : [];
  const hasMatching = page.some((s) => String(s).toLowerCase() === shell);
  if (!hasMatching && !o.userTrustOrigin) {
    // 页面只支持另一种主题：不允许它反色 shell UI，保持 shell 主题。
    return { effective: shell, allowPageOverride: false };
  }
  return { effective: shell, allowPageOverride: true };
}

// isRiskyInversionCss 粗判一段 CSS 是否在做"强制反色"。
function isRiskyInversionCss(css) {
  const s = String(css || '');
  if (!s) return false;
  // filter: invert(...) 是最常见的反色劫持手段。
  return /filter\s*:\s*invert\s*\(/i.test(s);
}

module.exports = {
  decideColorSchemeOverride,
  isRiskyInversionCss,
};
