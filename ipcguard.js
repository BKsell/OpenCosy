'use strict';

// ipcguard.js —— 主进程入站 IPC 的「发送帧来源」统一守卫内核。
//
// 威胁模型：
//   preload 侧（preloadpolicy）已经让远程网页拿不到 electronAPI，但那是“渲染端自我
//   克制”，不是安全边界：一旦渲染端有任何脚本执行偏差、调试入口、或未来有人给远程
//   上下文重新暴露 API，主进程绝不能默认信任入站 IPC。历史上 main.js 靠在每个
//   handler 里手写 isMainSender 兜底，124 个 handler 中就有 5 个证书例外通道漏写，
//   任意被浏览网页都能调用 approve-cert-exception 放行 TLS 例外（持久化 MITM）。
//
//   本模块把“这条入站消息来自哪个帧、是否受信”收敛成一个判定，并提供一个安装器：
//   包装 ipcMain.handle / on / once / handleOnce，在业务 listener 之前统一拦截。
//   策略是默认拒绝：只有受信帧能调用业务通道，其余一律不进入 handler。
//
// 受信帧只有两类：
//   shell —— 主窗口外壳 webContents（event.sender === mainWindow.webContents），
//            承载 file: 的 src/index.html，是浏览器自身 UI；
//   cosy  —— 帧地址为 cosy: 的内置页（新标签页 / 安全面板 / 内置错误页），即使它
//            跑在标签 WebContentsView 里也是浏览器自己的文档。
// 特别注意：标签视图同样可以 loadFile 打开“用户磁盘上的本地 html”，那种 file: 帧
//   不是外壳，归类为 local-file 并按不可信处理——不能仅凭 file: 协议就放权。

const policy = require('./preloadpolicy');

// 受信帧分三类：
//   shell         —— 主窗口外壳 webContents（event.sender === mainWindow.webContents），
//                    承载 file: 的 src/index.html，是浏览器自身 UI；
//   cosy          —— 帧地址为 cosy: 的内置页（新标签页 / 安全面板）；
//   internal-file —— 在标签视图里以 file: 加载、但物理路径位于应用安装目录内的内置
//                    静态页（如 src/error.html）。它不是外壳 webContents，却仍是浏览器
//                    自己的文档。
// 特别注意：标签视图也能 loadFile 打开“用户磁盘上的任意 html”，那种 file: 帧归类为
//   local-file 并按不可信处理——绝不能只凭 file: 协议就放权，必须核对路径在应用目录内。

const KIND_SHELL = 'shell';
const KIND_COSY = 'cosy';
const KIND_INTERNAL_FILE = 'internal-file';
const KIND_LOCAL_FILE = 'local-file';
const KIND_WEB = 'web';
const KIND_UNTRUSTED = 'untrusted';
const KIND_NONE = 'none';

const PRIVILEGED_KINDS = new Set([KIND_SHELL, KIND_COSY, KIND_INTERNAL_FILE]);

/**
 * 判定一个入站事件的发送帧属于哪一类。
 * @param {{sender?:object, senderFrame?:{url?:string}}|null} event Electron IpcMainEvent/InvokeEvent
 * @param {(event:object)=>boolean} isShellSender 是否为主窗口外壳 webContents
 * @param {(frameUrl:string)=>boolean} [isInternalFile] 判定 file: 帧是否为应用目录内的内置静态页
 * @returns {string}
 */
function classifySender(event, isShellSender, isInternalFile) {
  if (!event || typeof event !== 'object') return KIND_NONE;
  let shell = false;
  try {
    shell = typeof isShellSender === 'function' && !!isShellSender(event);
  } catch {
    shell = false;
  }
  if (shell) return KIND_SHELL;

  const frame = event.senderFrame;
  if (!frame || typeof frame.url !== 'string') return KIND_NONE;

  const proto = policy.parseProtocol(frame.url);
  if (proto === 'cosy:') return KIND_COSY;
  if (proto === 'file:') {
    let internal = false;
    try {
      internal = typeof isInternalFile === 'function' && !!isInternalFile(frame.url);
    } catch {
      internal = false;
    }
    // 无法确认位于应用目录内的 file: 帧，一律按用户本地文件处理，宁可信其不可信。
    return internal ? KIND_INTERNAL_FILE : KIND_LOCAL_FILE;
  }
  if (proto === 'http:' || proto === 'https:') return KIND_WEB;
  if (proto === '') return KIND_NONE;
  return KIND_UNTRUSTED;
}

/**
 * 受信帧（shell/cosy）才允许调用业务 IPC。
 * @param {string} kind
 * @returns {boolean}
 */
function isPrivilegedKind(kind) {
  return PRIVILEGED_KINDS.has(kind);
}

/**
 * 对一次入站调用做放行判定。
 * @param {string} channel 通道名
 * @param {object} event IPC 事件
 * @param {{isShellSender?:Function, allowAnyFrame?:Set<string>}} opts
 * @returns {{allow:boolean, kind:string, reason:string}}
 */
function decide(channel, event, opts) {
  const o = opts || {};
  // 极少数通道需要让任意帧也能“投递”（例如 CSP 上报，远程页也会发），这些通道的
  // handler 内部必须自行按帧来源再验一次；守卫只负责不在这里提前拦死。
  if (o.allowAnyFrame && o.allowAnyFrame.has(channel)) {
    return {
      allow: true,
      kind: classifySender(event, o.isShellSender, o.isInternalFileFrame),
      reason: 'allow-any-frame',
    };
  }
  const kind = classifySender(event, o.isShellSender, o.isInternalFileFrame);
  if (!isPrivilegedKind(kind)) {
    return { allow: false, kind, reason: kind === KIND_NONE ? 'no-frame' : 'unprivileged-frame' };
  }
  // 受信帧内部再按“通道 × 帧来源”做最小权限分级（由上层注入，默认放行以保持兼容）。
  if (typeof o.frameAllows === 'function') {
    let tierOk = true;
    try {
      tierOk = !!o.frameAllows(kind, channel);
    } catch {
      tierOk = false;
    }
    if (!tierOk) return { allow: false, kind, reason: 'channel-tier' };
  }
  return { allow: true, kind, reason: 'privileged' };
}

// 每个通道的拒绝计数，供上层做限流，避免恶意网页刷 IPC 把安全日志 / 磁盘打爆。
function createRateCounter() {
  const buckets = new Map();
  return {
    /**
     * @param {string} key 通常为 channel 或 channel+kind
     * @param {number} windowMs 时间窗
     * @param {number} maxInWindow 窗口内最大次数
     * @returns {boolean} 本次是否仍在阈值内（true=记录，false=超出应丢弃）
     */
    admit(key, windowMs, maxInWindow) {
      const now = Date.now();
      const b = buckets.get(key);
      if (!b || now - b.start >= windowMs) {
        buckets.set(key, { start: now, count: 1 });
        return true;
      }
      if (b.count >= maxInWindow) return false;
      b.count += 1;
      return true;
    },
    size() {
      return buckets.size;
    },
  };
}

/**
 * 安装入站 IPC 守卫：就地包装 ipcMain 的注册方法，使每个 listener 先经过来源判定。
 * 只包装实际存在的方法（不同 Electron 版本 handleOnce 可能缺失），并返回卸载函数。
 *
 * @param {object} ipcMain Electron ipcMain 单例
 * @param {object} opts
 * @param {(event:object)=>boolean} [opts.isShellSender] 主窗口外壳判定
 * @param {Set<string>} [opts.allowAnyFrame] 允许任意帧投递、由 handler 自验的通道
 * @param {(info:{channel:string, kind:string, reason:string, event:object})=>void} [opts.onReject]
 *        拒绝回调（用于安全事件记录）；回调自身异常被吞掉，绝不影响主流程
 * @returns {()=>void} 卸载函数（测试用）
 */
function installIpcGuard(ipcMain, opts) {
  const o = opts || {};
  const methods = ['handle', 'handleOnce', 'on', 'once'];
  const original = new Map();

  for (const method of methods) {
    if (typeof ipcMain[method] !== 'function') continue;
    original.set(method, ipcMain[method]);

    const register = original.get(method);
    const isInvokeKind = method === 'handle' || method === 'handleOnce';

    ipcMain[method] = function guardedRegister(channel, listener) {
      if (typeof listener !== 'function') {
        return register.call(this, channel, listener);
      }
      const wrapped = function guardedListener(event, ...args) {
        const verdict = decide(channel, event, o);
        if (!verdict.allow) {
          try {
            if (typeof o.onReject === 'function') {
              o.onReject({ channel, kind: verdict.kind, reason: verdict.reason, event });
            }
          } catch {}
          if (isInvokeKind) {
            // invoke 必须返回一个 rejected Promise，渲染端 await 会收到失败，
            // 而不是永远挂起；错误信息保持中性，不回显内部判定细节。
            return Promise.reject(new Error('IPC channel denied'));
          }
          return undefined; // on/once：直接吞掉，不进入业务 handler
        }
        return listener.apply(this, [event, ...args]);
      };
      return register.call(this, channel, wrapped);
    };
  }

  return function uninstall() {
    for (const [method, fn] of original) {
      ipcMain[method] = fn;
    }
  };
}

module.exports = {
  KIND_SHELL,
  KIND_COSY,
  KIND_INTERNAL_FILE,
  KIND_LOCAL_FILE,
  KIND_WEB,
  KIND_UNTRUSTED,
  KIND_NONE,
  classifySender,
  isPrivilegedKind,
  decide,
  createRateCounter,
  installIpcGuard,
};
