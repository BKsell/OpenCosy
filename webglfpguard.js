'use strict';

// webglfpguard.js —— WebGL 显卡指纹与调试扩展泄漏裁决内核。
//
// 威胁模型：
//   1. WEBGL_debug_renderer_info 返回 UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL，
//      直接暴露 GPU 型号（如 "ANGLE (NVIDIA RTX 4080)"）+ 驱动版本，是强硬件指纹，
//      配合屏幕/DPR 可长期跨站识别用户；
//   2. getParameter 枚举的 MAX_TEXTURE_SIZE、扩展列表、着色器精度、支持的扩展数量
//      组成次级指纹；
//   3. getSupportedExtensions 的排列与数量区分显卡代际；
//   4. 页面用多个离屏 canvas 高频读取做指纹刷新；
//   5. readPixels 读取渲染结果做绘图指令侧信道。
//
// 纯逻辑：决定哪些参数返回真值/泛化值/拒绝，并对读取频控。

const WG_DENY = 'deny';
const WG_ALLOW = 'allow';
const WG_SPOOF = 'spoof';

const WG_REASON = Object.freeze({
  BAD_ORIGIN: 'wg-bad-origin',
  BLOCKED_ORIGIN: 'wg-blocked-origin',
  RENDERER_INFO_REDACTED: 'wg-renderer-info-redacted',
  PARAMETER_QUANTIZED: 'wg-parameter-quantized',
  EXTENSION_DENIED: 'wg-extension-denied',
  READ_THROTTLED: 'wg-read-throttled',
  CONTEXT_LIMIT: 'wg-context-limit',
});

// 真正暴露硬件身份的调试扩展与参数键。
const DEBUG_EXTENSIONS = Object.freeze([
  'WEBGL_debug_renderer_info',
  'WEBGL_debug_shaders', // 可泄漏驱动翻译后的着色器
]);

const IDENTIFYING_PARAMS = Object.freeze({
  37445: 'UNMASKED_VENDOR_WEBGL',
  37446: 'UNMASKED_RENDERER_WEBGL',
});

// 需要量化/泛化的能力型参数（返回分桶值而非精确值）。
const QUANTIZED_PARAMS = Object.freeze(new Set([
  3379, // MAX_VERTEX_UNIFORM_VECTORS
  3386, // MAX_FRAGMENT_UNIFORM_VECTORS
  34076, // MAX_VARYING_VECTORS
  34921, // MAX_TEXTURE_IMAGE_UNITS
  34047, // MAX_VERTEX_TEXTURE_IMAGE_UNITS
  35660, // MAX_COMBINED_TEXTURE_IMAGE_UNITS
]));

function defaultWebglFpPolicy() {
  return {
    redactRendererInfo: true,
    genericVendorString: 'WebKit',
    genericRendererString: 'WebKit WebGL',
    quantizeCapabilityParams: true,
    blockDebugShaderExtension: true,
    minReadIntervalMs: 100,
    maxContextsPerOrigin: 8,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

// quantize 把能力值向下取到 2 的幂分桶，降低区分度。
function quantizePow2(v) {
  if (typeof v !== 'number' || !isFinite(v) || v <= 0) return v;
  let bucket = 1;
  while (bucket * 2 <= v) bucket *= 2;
  return bucket;
}

class WebglFpGuard {
  constructor(policy) {
    this.policy = policy || defaultWebglFpPolicy();
    this.lastRead = new Map();
    this.contextCount = new Map();
  }

  _key(ctx) {
    if (!ctx || typeof ctx !== 'object') return '';
    const key = originKey(ctx.origin);
    if (!key || ctx.blocked === true) return '';
    return key;
  }

  noteContextCreated(origin) {
    const key = originKey(origin);
    const n = (this.contextCount.get(key) || 0) + 1;
    this.contextCount.set(key, n);
    return n <= this.policy.maxContextsPerOrigin;
  }

  // decideGetParameter 裁决 gl.getParameter(pname)。
  decideGetParameter(ctx, pname) {
    const key = this._key(ctx);
    if (!key) return { decision: WG_DENY, reason: WG_REASON.BAD_ORIGIN };
    const now = ctx.now || 0;
    if (this.lastRead.has(key) && now - this.lastRead.get(key) < this.policy.minReadIntervalMs) {
      // 频控只针对身份型参数，避免误伤渲染热路径；这里对身份参数拒绝。
      if (Object.prototype.hasOwnProperty.call(IDENTIFYING_PARAMS, String(pname))) {
        return { decision: WG_DENY, reason: WG_REASON.READ_THROTTLED };
      }
    }
    this.lastRead.set(key, now);

    if (Object.prototype.hasOwnProperty.call(IDENTIFYING_PARAMS, String(pname))) {
      if (this.policy.redactRendererInfo) {
        const isVendor = IDENTIFYING_PARAMS[pname] === 'UNMASKED_VENDOR_WEBGL';
        return {
          decision: WG_SPOOF,
          reason: WG_REASON.RENDERER_INFO_REDACTED,
          value: isVendor ? this.policy.genericVendorString : this.policy.genericRendererString,
        };
      }
    }
    if (QUANTIZED_PARAMS.has(pname) && this.policy.quantizeCapabilityParams) {
      return { decision: WG_SPOOF, reason: WG_REASON.PARAMETER_QUANTIZED, transform: 'pow2' };
    }
    return { decision: WG_ALLOW, reason: '' };
  }

  // applyParameter 供上层在拿到真值后做量化。
  applyParameter(pname, realValue) {
    if (QUANTIZED_PARAMS.has(pname) && this.policy.quantizeCapabilityParams) {
      return quantizePow2(realValue);
    }
    return realValue;
  }

  // decideExtension 裁决 getExtension / getSupportedExtensions 中的敏感项。
  decideExtension(name) {
    const n = String(name || '').toLowerCase();
    if (n === 'webgl_debug_renderer_info' && this.policy.redactRendererInfo) {
      return { allowed: false, reason: WG_REASON.EXTENSION_DENIED };
    }
    if (n === 'webgl_debug_shaders' && this.policy.blockDebugShaderExtension) {
      return { allowed: false, reason: WG_REASON.EXTENSION_DENIED };
    }
    return { allowed: true, reason: '' };
  }

  // filterExtensionList 从 getSupportedExtensions 列表里剔除敏感扩展。
  filterExtensionList(list) {
    const removed = [];
    const kept = [];
    for (const ext of list || []) {
      const d = this.decideExtension(ext);
      if (d.allowed) kept.push(ext);
      else removed.push(ext);
    }
    return { kept, removed };
  }
}

module.exports = {
  WG_ALLOW, WG_DENY, WG_SPOOF, WG_REASON,
  DEBUG_EXTENSIONS, IDENTIFYING_PARAMS, QUANTIZED_PARAMS,
  defaultWebglFpPolicy, originKey, quantizePow2, WebglFpGuard,
};
