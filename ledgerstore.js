'use strict';

// ledgerstore.js —— 主进程各类安全台账 / 设置的统一持久化内核。
//
// 背景：cookie、PNA、指纹、DoH、协议决策、安全事件、CSP、响应头评级、请求日志、
// 品牌仿冒、证书例外、下载哈希/风险、权限决策、缩放源等十几个 JSON 台账，之前
// 各自手写了一份“readFile + JSON.parse + try/catch 回退”和“写 .tmp + rename”，
// 还各自维护一个防抖定时器。问题有三：
//   1. 重复样板十几份，任何一处加固（有界读取 / fsync）都得改十几遍，必然漏；
//   2. 原来的“写 tmp 再 rename”没有 fsync：进程写完、rename 成功后立刻掉电，
//      数据可能仍停留在页缓存，重启后拿到空文件或半截 JSON；
//   3. 读取一律 readFileSync 整读：台账文件被外部塞成 GB 级会直接把主进程撑爆。
//
// 本模块不依赖 Electron，只依赖 fs，可直接 node --test：
//   readJSONStore   有界读取 + 解析 + 回退（stat 限大小，超限按损坏处理）；
//   atomicWrite     fd 写入 + fsync 文件 + rename + 尽力 fsync 目录的崩溃安全原子写；
//   writeJSONStore  atomicWrite 的 JSON 包装；
//   createJSONStore 把“只加载一次 + 防抖落盘 + hydrate/serialize”收成一份声明。

const fs = require('fs');
const path = require('path');

// 台账 JSON 的读取上限（8MiB）。这些文件正常几十~几百 KiB，刻意取宽，只拦被塞成
// 巨值、一读就把主进程内存吃光的损坏/恶意文件（炸内存才拦），不跟正常台账过不去。
const DEFAULT_MAX_BYTES = 8 << 20;

function isMissingFileError(err) {
  return !!err && (err.code === 'ENOENT' || err.code === 'ENOTDIR');
}

// resolveMaxBytes 统一处理非法/缺省上限：0/负数/非数字一律回落到默认值，
// 避免调用方传 0 进来把“有界读取”变成“读 0 字节”的假安全。
function resolveMaxBytes(maxBytes) {
  return Number.isFinite(maxBytes) && maxBytes > 0 ? maxBytes : DEFAULT_MAX_BYTES;
}

// readBoundedText 先 stat 限大小、再整读（台账本来就是小文本，整读即可），
// 实际读取超过上限也判失败，防止 stat 与读之间文件被撑大（TOCTOU）。
function readBoundedText(filePath, maxBytes) {
  const limit = resolveMaxBytes(maxBytes);
  let size = -1;
  try {
    size = fs.statSync(filePath).size;
  } catch (err) {
    if (isMissingFileError(err)) return { missing: true };
    throw err;
  }
  if (size > limit) {
    const err = new Error(`ledger store too large: ${filePath} ${size} > ${limit}`);
    err.code = 'LEDGER_TOO_LARGE';
    throw err;
  }
  const text = fs.readFileSync(filePath, 'utf8');
  if (Buffer.byteLength(text, 'utf8') > limit) {
    const err = new Error(`ledger store grew past limit while reading: ${filePath}`);
    err.code = 'LEDGER_TOO_LARGE';
    throw err;
  }
  return { missing: false, text };
}

// readJSONStore 读取并解析一个 JSON 台账。
//   - 文件不存在：返回 fallback（不报错，台账首次运行本就没有文件）；
//   - 文件超大 / JSON 损坏：默认也返回 fallback（保证主进程不被坏文件拖崩），
//     但调用方可传 onCorrupt 收到错误用于登记安全事件；
//   - 显式 returnFallBackOnError:false 时把错误抛出（用于需要感知损坏的场景）。
function readJSONStore(filePath, fallback, options) {
  const opts = options || {};
  let picked;
  try {
    picked = readBoundedText(filePath, opts.maxBytes);
  } catch (err) {
    if (typeof opts.onCorrupt === 'function') opts.onCorrupt(err);
    if (opts.throwOnError) throw err;
    return fallback;
  }
  if (picked.missing) return fallback;
  try {
    return JSON.parse(picked.text);
  } catch (err) {
    if (typeof opts.onCorrupt === 'function') opts.onCorrupt(err);
    if (opts.throwOnError) throw err;
    return fallback;
  }
}

// fsyncDirectory 尽力把目录项变更（rename）落盘。目录 fsync 在不同平台支持不一，
// Windows 上对目录句柄 fsync 可能直接报错——这里任何失败都吞掉，文件本身已 fsync，
// 目录 fsync 只是进一步缩小掉电窗口，不能让它反过来影响正常写入。
function fsyncDirectory(dirPath) {
  let dirfd;
  try {
    dirfd = fs.openSync(dirPath, 'r');
    fs.fsyncSync(dirfd);
  } catch {
    // 平台不支持目录 fsync：文件内容已 fsync，可接受。
  } finally {
    if (dirfd !== undefined) {
      try { fs.closeSync(dirfd); } catch {}
    }
  }
}

// atomicWrite 崩溃安全原子写：写临时文件 → fsync 文件数据 → rename 覆盖 →
// 尽力 fsync 目录。任何一步失败都尝试清掉残留 tmp，绝不在原地截断目标文件。
// tmp 文件名带 pid 与随机串，避免同一台账被多个写入者（或历史残留）互相踩。
function atomicWrite(filePath, data, options) {
  const opts = options || {};
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(dir,
    `.${path.basename(filePath)}.${process.pid}.${Math.random().toString(36).slice(2, 8)}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'w', opts.mode || 0o600);
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } catch (err) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  try {
    fs.closeSync(fd);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  try {
    fs.renameSync(tmp, filePath);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
  fsyncDirectory(dir);
}

// writeJSONStore 把对象序列化为 JSON 后原子写入。pretty=true 用两空格缩进，
// 用于希望用户可直接翻看的设置文件；台账默认紧凑，减少体积与写放大。
function writeJSONStore(filePath, value, options) {
  const opts = options || {};
  const text = JSON.stringify(value, null, opts.pretty ? 2 : 0);
  atomicWrite(filePath, text, { mode: opts.mode });
}

// createJSONStore 收口一个台账的“只加载一次 + hydrate 还原 + 防抖原子落盘”。
// 返回：
//   ensureLoaded() 首次调用读取文件并交给 hydrate(data) 还原到调用方的数据结构，
//                  之后调用直接返回（懒加载，且只读一次）；
//   schedule()     防抖触发一次 serialize() → writeJSONStore；
//   flush()        立即落盘一次（可用于退出前），返回是否成功；
//   loaded         当前是否已完成首次加载。
function createJSONStore(options) {
  const opts = options || {};
  if (!opts.file) throw new Error('createJSONStore 需要 file');
  const delay = Number.isFinite(opts.delay) && opts.delay >= 0 ? opts.delay : 300;
  let loaded = false;
  let timer = null;

  function ensureLoaded() {
    if (loaded) return;
    loaded = true;
    if (typeof opts.hydrate !== 'function') return;
    const data = readJSONStore(opts.file, undefined, {
      maxBytes: opts.maxBytes,
      onCorrupt: opts.onCorrupt,
    });
    if (data === undefined) return;
    try {
      opts.hydrate(data);
    } catch (err) {
      if (typeof opts.onCorrupt === 'function') opts.onCorrupt(err);
    }
  }

  function flush() {
    if (typeof opts.serialize !== 'function') return false;
    let value;
    try {
      value = opts.serialize();
    } catch {
      return false;
    }
    if (value === undefined) return false;
    try {
      writeJSONStore(opts.file, value, { pretty: opts.pretty, mode: opts.mode });
      return true;
    } catch {
      return false;
    }
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      flush();
    }, delay);
    if (typeof timer.unref === 'function') timer.unref();
  }

  return {
    ensureLoaded,
    schedule,
    flush,
    get loaded() { return loaded; },
  };
}

module.exports = {
  DEFAULT_MAX_BYTES,
  readJSONStore,
  readBoundedText,
  atomicWrite,
  writeJSONStore,
  createJSONStore,
};
