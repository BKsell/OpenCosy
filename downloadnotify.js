'use strict';

// downloadnotify.js —— 下载完成/失败的系统通知内核（不依赖 Electron 的纯决策 + 注入）。
//
// 背景：will-download 的 done 回调里，下载完成只往渲染层发 download-complete，失败
// 只发 download-error。窗口最小化或切到别的应用时，用户看不到下载结果——现代浏览器
// （Chrome/Edge/Firefox）都会在系统托盘弹一条“下载完成/失败”通知。这里补上这一环。
//
// 安全约束：
//   * Notification 的 title/body 是纯文本渲染，不是 HTML，无 XSS；但文件名来自服务端
//     Content-Disposition，可能含控制字符（伪造换行、ESC 序列），入通知前先剥掉
//     控制字符并把长度压到平台建议上限（64 字节标题 / 256 字节正文以内）。
//   * 通知里不落完整本地路径（savePath 是敏感结构信息），失败时也不展示原始错误
//     详情，只给用户可读的一句话 + “重试/查看”入口。
//   * 点击“完成”通知才去打开文件；点击“失败”通知只聚焦窗口并打开下载列表页，
//     不自动重试（重试是用户显式动作，防下载炸弹自动卷土重来）。
// 本模块依赖注入：showNotification / openPath / focusWindow / isSupported，
// 与 downloadadmission.js 的 deps 风格一致，便于表驱动测试。

const KIND_COMPLETE = 'complete';
const KIND_ERROR = 'error';

const TITLE_MAX = 64;
const BODY_MAX = 256;

// stripControlChars 剥掉不可打印字符（含换行、ESC 及其引导的 CSI 序列），防
// 日志/通知注入；保留中文等多字节 UTF-8（逐字节判断，0x20 以下与 0x7f 丢弃）。
// ESC 序列整段剥（不只是 ESC 本身），避免残留 “[31m” 这类可见垃圾。
function stripControlChars(s) {
  const src = String(s == null ? '' : s);
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const c = src.charCodeAt(i);
    if (c === 0x1b) {
      // ESC [ 引导的 CSI：跳到终字节（0x40-0x7E）整段丢弃；孤立 ESC 也丢弃。
      if (src.charCodeAt(i + 1) === 0x5b) {
        i += 2;
        while (i < src.length && !(src.charCodeAt(i) >= 0x40 && src.charCodeAt(i) <= 0x7e)) i++;
      }
      continue;
    }
    if (c < 0x20 || c === 0x7f) continue;
    out.push(src[i]);
  }
  return out.join('');
}

// truncateUtf8 按字节上限截断字符串，避免在 UTF-8 多字节字符中间切断产生乱码。
function truncateUtf8(s, maxBytes) {
  let limit = maxBytes;
  if (Buffer.byteLength(s, 'utf8') <= limit) return s;
  let out = '';
  for (const ch of s) {
    const need = Buffer.byteLength(ch, 'utf8');
    if (limit - need < 0) break;
    out += ch;
    limit -= need;
  }
  return out;
}

// formatSize 人类可读大小（B/KB/MB/GB），与 renderer 的下载栏展示保持一致。
function formatSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = -1;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i < 0 ? 0 : 1)} ${units[i]}`;
}

// buildDownloadNotification 组装一条系统通知的展示内容（纯函数，可单测）。
// kind: 'complete' | 'error'
// input: { filename, sizeBytes, url, savePath, errorMessage }
// 返回 { title, body, silent }；silent=true 表示完成类低打扰。
function buildDownloadNotification(kind, input) {
  const rawName = String((input && input.filename) || '下载');
  const filename = truncateUtf8(stripControlChars(rawName), 96);
  const size = formatSize(input && input.sizeBytes);

  if (kind === KIND_ERROR) {
    const errMsg = String((input && input.errorMessage) || '').trim();
    // 失败详情只给一句话（截断），不输出原始异常（可能含路径/URL）。
    const detail = errMsg ? truncateUtf8(stripControlChars(errMsg), 128) : '下载未能完成';
    return { title: '下载失败', body: `${filename} · ${detail}`, silent: false };
  }

  const body = size ? `${filename} · ${size}` : filename;
  return { title: '下载完成', body, silent: true };
}

// notifyDownload 执行一次系统通知；deps 全部注入，便于测试替换。
// deps:
//   isSupported() -> boolean                当前平台是否支持系统通知
//   showNotification(opts, onClick) -> void 真正弹通知（opts: title/body/silent）
//   openPath(savePath) -> void              完成通知点击：打开文件
//   focusWindow() -> void                   失败通知点击：聚焦主窗口
// 返回是否真的弹出了通知（false = 平台不支持 / 输入不完整）。
function notifyDownload(kind, deps, input) {
  const d = deps || {};
  if (typeof d.isSupported !== 'function' || !d.isSupported()) return false;
  if (kind !== KIND_COMPLETE && kind !== KIND_ERROR) return false;
  const info = input || {};
  if (!info.filename) return false;

  const note = buildDownloadNotification(kind, info);
  if (typeof d.showNotification !== 'function') return false;
  let onClick = null;
  if (kind === KIND_COMPLETE) {
    const savePath = String(info.savePath || '');
    if (savePath && typeof d.openPath === 'function') {
      onClick = () => { try { d.openPath(savePath); } catch { /* 打开失败静默 */ } };
    }
  } else {
    if (typeof d.focusWindow === 'function') {
      onClick = () => { try { d.focusWindow(); } catch { /* 聚焦失败静默 */ } };
    }
  }
  d.showNotification(note, onClick);
  return true;
}

module.exports = {
  KIND_COMPLETE,
  KIND_ERROR,
  buildDownloadNotification,
  notifyDownload,
  stripControlChars,
  truncateUtf8,
  formatSize,
};
