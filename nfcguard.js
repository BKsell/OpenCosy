'use strict';

// nfcguard.js —— Web NFC（NDEFReader.scan/write）授权与 NDEF 记录裁决内核。
//
// 威胁模型：
//   1. scan() 在页面获得权限后可常驻读取周边标签 UID，做物理邻近追踪与门禁/工牌关联；
//   2. write() 可把任意 URL/文本写入靠近的标签：把合法支付/门禁标签改写成钓鱼链接或
//      外部 scheme，用户下一次触碰即被劫持；写入的 URL 若是 http/外部 scheme 危害更大；
//   3. NDEF record 的 mediaType / recordType 携带超长或控制字符，触发底层解析异常；
//   4. 无手势/页面不可见仍持续扫描，构成后台无线感知；
//   5. 写入绝对大小超过 NDEF 上限是脏数据。
//
// 纯逻辑。

const NFC_ALLOW = 'allow';
const NFC_DENY = 'deny';

const NFC_REASON = Object.freeze({
  BAD_CONTEXT: 'nfc-bad-context',
  NO_GESTURE: 'nfc-no-gesture',
  CROSS_ORIGIN_SUBFRAME: 'nfc-cross-origin-subframe',
  INSECURE_ORIGIN: 'nfc-insecure-origin',
  SCAN_WHEN_HIDDEN: 'nfc-scan-when-hidden',
  PERSISTENT_SCAN: 'nfc-persistent-scan',
  WRITE_NOT_VISIBLE: 'nfc-write-not-visible',
  WRITE_REQUIRES_GESTURE: 'nfc-write-requires-gesture',
  BAD_RECORD: 'nfc-bad-record',
  RECORD_TYPE_NOT_ALLOWED: 'nfc-record-type-not-allowed',
  INSECURE_RECORD_URL: 'nfc-insecure-record-url',
  EXTERNAL_SCHEME_RECORD: 'nfc-external-scheme-record',
  MEDIA_TYPE_CONTROL_CHAR: 'nfc-media-type-control-char',
  MEDIA_TYPE_TOO_LONG: 'nfc-media-type-too-long',
  PAYLOAD_TOO_LARGE: 'nfc-payload-too-large',
});

// NDEF 标准记录类型。
const NFC_KNOWN_TYPES = Object.freeze(['text', 'url', 'mime', 'absolute-url', 'smart-poster', 'empty']);
const NFC_WRITABLE_TYPES = Object.freeze(['text', 'url', 'mime', 'absolute-url', 'smart-poster']);
// NDEF 标签常见可用载荷上限（保守取 NDEF 消息 32KB）。
const NFC_MAX_MESSAGE_BYTES = 32 * 1024;
const NFC_MAX_MEDIA_TYPE = 255;

function defaultNfcPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockCrossOriginSubframe: true,
    allowScanOnlyWhenVisible: true,
    blockPersistentBackgroundScan: true,
    writableRecordTypes: NFC_WRITABLE_TYPES.slice(),
    requireHttpsRecordUrl: true,
    blockExternalSchemeRecord: true,
    maxMessageBytes: NFC_MAX_MESSAGE_BYTES,
  };
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

function recordUrlScheme(url) {
  if (typeof url !== 'string') return '';
  const colon = url.indexOf(':');
  if (colon <= 0) return '';
  return url.slice(0, colon).toLowerCase();
}

// validateRecord 校验单条 NDEF 记录（写入内容）。
function validateRecord(record, pol) {
  if (!record || typeof record !== 'object') return { ok: false, reason: NFC_REASON.BAD_RECORD };
  const t = record.recordType;
  if (typeof t !== 'string' || NFC_KNOWN_TYPES.indexOf(t) < 0) {
    return { ok: false, reason: NFC_REASON.RECORD_TYPE_NOT_ALLOWED, recordType: t };
  }
  if (pol.writableRecordTypes.indexOf(t) < 0) {
    return { ok: false, reason: NFC_REASON.RECORD_TYPE_NOT_ALLOWED, recordType: t };
  }

  const data = record.data;
  let size = 0;
  if (typeof data === 'string') {
    size = byteLen(data);
  } else if (data && typeof data.byteLength === 'number') {
    size = data.byteLength;
  } else if (data && typeof data.size === 'number') {
    size = data.size;
  }
  if (size > pol.maxMessageBytes) return { ok: false, reason: NFC_REASON.PAYLOAD_TOO_LARGE, bytes: size };

  if (t === 'url' || t === 'absolute-url' || t === 'smart-poster') {
    const url = typeof record.data === 'string' ? record.data : '';
    const scheme = recordUrlScheme(url);
    if (scheme !== 'https' && scheme !== 'http') {
      return { ok: false, reason: NFC_REASON.EXTERNAL_SCHEME_RECORD, scheme };
    }
    if (pol.requireHttpsRecordUrl && scheme !== 'https') {
      return { ok: false, reason: NFC_REASON.INSECURE_RECORD_URL, url: url };
    }
  }

  if (t === 'mime') {
    const mt = typeof record.mediaType === 'string' ? record.mediaType : '';
    if (mt.length === 0 || mt.length > NFC_MAX_MEDIA_TYPE) {
      return { ok: false, reason: NFC_REASON.MEDIA_TYPE_TOO_LONG };
    }
    if (hasControlChar(mt)) return { ok: false, reason: NFC_REASON.MEDIA_TYPE_CONTROL_CHAR };
  }
  return { ok: true, bytes: size };
}

class NfcGuard {
  constructor(policy) {
    this.policy = policy || defaultNfcPolicy();
    this.activeScans = new Map(); // origin -> {backgrounded}
  }

  _gateContext(ctx, needGesture) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return NFC_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return NFC_REASON.INSECURE_ORIGIN;
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) return NFC_REASON.CROSS_ORIGIN_SUBFRAME;
    if (needGesture && pol.requireUserGesture && ctx.userGesture !== true) return NFC_REASON.NO_GESTURE;
    return '';
  }

  // decideScan 裁决开始扫描。
  decideScan(ctx, options) {
    const bad = this._gateContext(ctx, true);
    if (bad) return { decision: NFC_DENY, reason: bad };
    const pol = this.policy;
    if (pol.allowScanOnlyWhenVisible && ctx.visible === false) {
      return { decision: NFC_DENY, reason: NFC_REASON.SCAN_WHEN_HIDDEN };
    }
    const opt = options && typeof options === 'object' ? options : {};
    if (pol.blockPersistentBackgroundScan && opt.persistent === true && ctx.visible !== true) {
      return { decision: NFC_DENY, reason: NFC_REASON.PERSISTENT_SCAN };
    }
    if (this.activeScans.has(ctx.origin) && opt.renew !== true) {
      // 重复 scan 不单独拒绝，但若调用方声明独占则视为持久化企图。
      if (opt.exclusive === true) return { decision: NFC_DENY, reason: NFC_REASON.PERSISTENT_SCAN };
    }
    this.activeScans.set(ctx.origin, { backgrounded: ctx.visible === false });
    return { decision: NFC_ALLOW, reason: '' };
  }

  // decideWrite 裁决写入一组记录。
  decideWrite(ctx, records) {
    const bad = this._gateContext(ctx, true);
    if (bad) return { decision: NFC_DENY, reason: bad };
    if (ctx.visible !== true) return { decision: NFC_DENY, reason: NFC_REASON.WRITE_NOT_VISIBLE };

    const list = Array.isArray(records) ? records : null;
    if (!list || list.length === 0) return { decision: NFC_DENY, reason: NFC_REASON.BAD_RECORD };
    let total = 0;
    for (let i = 0; i < list.length; i++) {
      const v = validateRecord(list[i], this.policy);
      if (!v.ok) return Object.assign({ decision: NFC_DENY, index: i }, v);
      total += v.bytes || 0;
      if (total > this.policy.maxMessageBytes) {
        return { decision: NFC_DENY, reason: NFC_REASON.PAYLOAD_TOO_LARGE, bytes: total };
      }
    }
    return { decision: NFC_ALLOW, reason: '', bytes: total };
  }

  // pageHidden 由生命周期事件调用：隐藏后仍在扫描则判定后台扫描。
  pageHidden(origin) {
    const cur = this.activeScans.get(origin);
    if (cur) cur.backgrounded = true;
    return this.policy.blockPersistentBackgroundScan === true && !!cur && cur.backgrounded === true;
  }

  endScan(origin) {
    this.activeScans.delete(origin);
  }
}

module.exports = {
  NFC_ALLOW, NFC_DENY, NFC_REASON,
  NFC_KNOWN_TYPES, NFC_WRITABLE_TYPES, NFC_MAX_MESSAGE_BYTES, NFC_MAX_MEDIA_TYPE,
  defaultNfcPolicy, byteLen, hasControlChar, recordUrlScheme, validateRecord, NfcGuard,
};
