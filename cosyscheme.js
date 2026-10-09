'use strict';

// cosyscheme.js —— cosy: 内置页协议与 file: 本地文件协议的安全收口内核。
//
// 威胁模型：
//   1) 浏览器的设置/安全/权限/下载等内置页跑在自定义的 cosy: 协议上。自定义 scheme 若
//      不在 app ready 之前用 protocol.registerSchemesAsPrivileged 登记，Chromium 会把它
//      当作“非标准、非安全”协议：host/路径解析走非标准规则，既不能被正确视为安全上下
//      文（Service Worker、部分 Web Crypto、credentials=include 等行为异常），CSP 与同源
//      判定也会偏松或不一致。承载敏感 UI 的内置页必须是 standard + secure + CORS +
//      fetch 可用。
//
//   2) 主进程覆盖了 file: 协议来限制网页可读的本地目录。旧实现用手写
//      decodeURIComponent(url.substr(7)) 再 path.resolve，没有剥离 URL 的 host 段：
//        file://localhost/C:/x   ->  //localhost/C:/x
//        file://server/share/x  ->  //server/share/x （UNC 远程共享）
//      在 Windows 上这些会被当成 UNC/异常路径；同时 fileURLToPath 对盘符/百分号编码的
//      处理远比手写切割严谨。这里统一用 WHATWG URL + fileURLToPath 归一，并拒绝任何带
//      远程 host（非空且非 localhost）的 file: 请求，把可访问路径严格收敛进允许目录。
//
// 本模块只做纯判定/路径解析，真正的 protocol.register* 调用在 main.js（ready 前登记
// 特权，ready 后注册处理器），便于用 node:test 直接验证。

const path = require('path');
const { pathToFileURL, fileURLToPath } = require('url');

const COSY_SCHEME = 'cosy';
const LOCAL_FILE_HOSTS = new Set(['', 'localhost', '127.0.0.1', '[::1]']);

// 内置页 host -> 相对 src 的文件。集中成单一白名单，未命中一律回落到 newtab，
// 不允许用 URL 的 path/query 直接拼磁盘路径（从根上杜绝 cosy: 路径穿越）。
const COSY_PAGES = Object.freeze({
  setting: 'settings.html',
  newtab: 'newtab.html',
  extensions: 'extensions.html',
  version: 'version.html',
  sitedata: 'sitedata.html',
  permissions: 'permissions.html',
  security: 'security.html',
  hashes: 'hashes.html',
  download: 'download/index.html',
  downloadlist: 'downloadlist.html',
  taskmanager: 'taskmanager.html',
});
const DEFAULT_PAGE = 'newtab.html';

// privilegedSchemeOptions 给出 registerSchemesAsPrivileged 需要的最小安全特权集。
// standard  -> 按 RFC 3986 解析 host/path，cosy://setting/a 与 cosy://setting/a/ 同源规则正确；
// secure    -> 视为安全上下文（等同 https），敏感 Web API 与 CSP 语义正常；
// corsEnabled / supportFetchAPI -> 内置页内 fetch 走标准同源/CORS，不放大跨源读取；
// stream 默认 false，bypassCSP 绝不开启。
function privilegedSchemeOptions() {
  return [{
    scheme: COSY_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: false,
    },
  }];
}

// normalizeHost 把 hostname 收敛成小写、去末尾点、去方括号（IPv6 形式不用于 cosy）。
function normalizeHost(rawHost) {
  let h = String(rawHost == null ? '' : rawHost).trim().toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

// resolveCosyPage 依据白名单把 cosy URL 映射到“相对 src 的文件”。未知 host 回落
// newtab；任何 query/hash/path 都不参与文件选择。返回 {host,file,known}。
function resolveCosyPage(rawUrl) {
  let host = '';
  try {
    host = normalizeHost(new URL(rawUrl).hostname);
  } catch {
    return { host: '', file: DEFAULT_PAGE, known: false };
  }
  if (Object.prototype.hasOwnProperty.call(COSY_PAGES, host)) {
    return { host, file: COSY_PAGES[host], known: true };
  }
  return { host, file: DEFAULT_PAGE, known: false };
}

// resolveCosyFilePath 在 resolveCosyPage 基础上拼出绝对磁盘路径。srcDir 必须是内置页
// 所在目录（绝对路径），结果用 path.resolve 锁死在 srcDir 内（白名单值本就不含 .. ）。
function resolveCosyFilePath(rawUrl, srcDir) {
  const r = resolveCosyPage(rawUrl);
  return { ...r, absolutePath: path.resolve(srcDir, r.file) };
}

// isPathInsideDir 判断 target 是否已规范化地落在某一根目录内（含根本身）。
// 统一分隔符后做“等于根”或“根 + 分隔符”前缀比较，避免 /safe-evil 被误判进 /safe。
function isPathInsideDir(target, dir) {
  const norm = p => path.resolve(p);
  const t = norm(target);
  const d = norm(dir);
  if (t === d) return true;
  const withSep = d.endsWith(path.sep) ? d : d + path.sep;
  return t.startsWith(withSep);
}

// resolveAllowedFileUrl 把一个 file: URL 解析成磁盘路径并校验是否落在允许目录内。
// 返回 {ok,path,reason}。绝不抛异常（畸形 URL -> ok:false）。
//   reason: non-file-scheme / malformed / remote-host / traversal / outside-allowed
function resolveAllowedFileUrl(rawUrl, allowedDirs) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, path: '', reason: 'malformed' };
  }
  if (u.protocol !== 'file:') {
    return { ok: false, path: '', reason: 'non-file-scheme' };
  }
  // 拒绝远程/UNC host：file://server/share 这类指向网络共享的请求不放行。
  // 空 host（file:///C:/...、file:///tmp/...）与 localhost 才是本机文件。
  if (!LOCAL_FILE_HOSTS.has(u.hostname.toLowerCase())) {
    return { ok: false, path: '', reason: 'remote-host' };
  }

  let filePath;
  try {
    filePath = fileURLToPath(u);
  } catch {
    return { ok: false, path: '', reason: 'malformed' };
  }
  filePath = path.resolve(filePath);

  const dirs = Array.isArray(allowedDirs) ? allowedDirs : [];
  for (const dir of dirs) {
    if (isPathInsideDir(filePath, dir)) {
      return { ok: true, path: filePath, reason: '' };
    }
  }
  return { ok: false, path: filePath, reason: 'outside-allowed' };
}

// fileUrlFromPath 主要用于测试与诊断：把绝对路径转回 file: URL。
function fileUrlFromPath(p) {
  return pathToFileURL(path.resolve(p)).href;
}

module.exports = {
  COSY_SCHEME,
  LOCAL_FILE_HOSTS,
  COSY_PAGES,
  DEFAULT_PAGE,
  privilegedSchemeOptions,
  normalizeHost,
  resolveCosyPage,
  resolveCosyFilePath,
  isPathInsideDir,
  resolveAllowedFileUrl,
  fileUrlFromPath,
};
