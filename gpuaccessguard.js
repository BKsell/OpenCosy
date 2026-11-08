'use strict';

// gpuaccessguard.js —— GPU 信息更新、GPU 进程崩溃、无障碍支持变化等“系统级”
// app/webContents 事件的归一与节流内核。
//
// 威胁模型：
//   浏览器主进程还会收到几类与具体网页弱关联、但具有安全 / 稳定性意义的系统事件：
//     - app 'gpu-info-update'：Chromium 重新枚举 GPU 后触发，auxAttributes 里带着
//       GL_RENDERER / 驱动版本 / 厂商等字符串。这些字符串来自驱动 / 硬件层，若原样
//       灌进审计行或渲染层界面，超长串与 CR/LF 可造成日志折行伪造与 UI 撑爆。
//     - app 'gpu-process-crashed'(event, killed)：GPU 进程崩溃 / 被杀。它与
//       child-process-gone(type==='GPU') 语义重叠，且崩溃恢复时可能在短时间内反复
//       触发；若每次都落审计 + 弹 UI，会形成崩溃风暴下的二次资源耗尽。
//     - app 'accessibility-support-changed'(event, enabled)：系统辅助功能（读屏等）
//       被打开 / 关闭。开启辅助功能会改变渲染路径并可能使自动化 / 注入更容易挂钩，
//       属于值得留痕的环境状态变化，但抖动切换不应刷爆日志。
//
// 本模块只做纯判定：字段白名单 + 限长清洗、崩溃去重节流、无障碍状态沿归一。
// 时间窗哨兵约定 now < 0 表示不节流（逐条记录），便于在基准时间 0 附近确定性测试。

const ACTION_RECORD = 'record';
const ACTION_SUPPRESS = 'suppress';

// GPU 崩溃事件默认冷却窗：5 分钟。GPU 进程偶发崩溃会自动重启，5 分钟内的重复
// 崩溃只计数，避免崩溃风暴反复落审计 / 弹窗。
const DEFAULT_GPU_CRASH_COOLDOWN_MS = 5 * 60 * 1000;

// 单个 GPU 字段字符串值的长度上限（驱动名 / 渲染器串通常 < 200）。
const MAX_GPU_FIELD_CHARS = 200;

// 从 auxAttributes 中允许保留的字段白名单。只保留与“是否走硬件加速 / 何种后端”
// 有关的确定字段；任何不在表内的键（驱动可能附带的自由文本 / 调试串）一律丢弃，
// 从源头避免把硬件层不可信字符串带入审计 / UI。
const GPU_BOOLEAN_FIELDS = new Set([
  'canSupportOpenGL',
  'canSupportVulkan',
  'gpuAccessibilitySupportEnabled',
  'softwareRendering',
  'metalDisabled',
  'passthroughIntelDecoderEnabled',
  'videoEncodeUsesTexture',
]);

const GPU_STRING_FIELDS = new Set([
  'glRenderer',
  'glVendor',
  'glVersion',
  'gpuRenderingActive',
  'vulkanVersion',
  'errorReason',
  'resetReason',
]);

// clampField 清洗单个字符串字段：去 CR/LF、限长。
function clampField(value, max) {
  let s = String(value);
  s = s.replace(/[\r\n]+/g, ' ');
  if (s.length > max) s = s.slice(0, max) + '…';
  return s;
}

// sanitizeGPUInfo 按白名单清洗 GPU auxAttributes。
// 返回 { fields: 仅保留的安全键值, dropped: 被丢弃的字段数 }。不抛异常。
function sanitizeGPUInfo(aux) {
  const out = { fields: {}, dropped: 0, kept: 0 };
  if (!aux || typeof aux !== 'object') {
    return out;
  }
  // 只处理普通对象自身可枚举键，避免沿原型链取值。
  for (const key of Object.keys(aux)) {
    const value = aux[key];
    if (GPU_BOOLEAN_FIELDS.has(key)) {
      out.fields[key] = value === true;
      out.kept++;
      continue;
    }
    if (GPU_STRING_FIELDS.has(key)) {
      if (typeof value !== 'string' && typeof value !== 'number') {
        out.dropped++;
        continue;
      }
      out.fields[key] = clampField(value, MAX_GPU_FIELD_CHARS);
      out.kept++;
      continue;
    }
    // 非白名单键：不保留其内容，只计数。
    if (value !== undefined && value !== null) {
      out.dropped++;
    }
  }
  return out;
}

// createCrashState 创建 GPU 崩溃去重状态。
function createCrashState() {
  return { lastSeen: -1, lastKey: '', count: 0, suppressed: 0 };
}

// crashKey 归一一次崩溃的签名：被杀(killed)与 reason 区分。
function crashKey(input) {
  const inp = input || {};
  const killed = inp.killed === true ? 'killed' : 'crashed';
  let reason = '';
  if (typeof inp.reason === 'string') {
    reason = inp.reason.replace(/[\r\n]+/g, ' ').slice(0, 48);
  }
  return `${killed}:${reason}`;
}

// decideGPUCrash 裁决一次 GPU 进程崩溃 / 被杀事件是否需要落审计 / 通知。
//   input: { killed: boolean, reason?: string }
//   now < 0 时不节流，逐条记录。
function decideGPUCrash(state, input, now, cooldownMs) {
  const st = state || createCrashState();
  const cool = (typeof cooldownMs === 'number' && cooldownMs > 0)
    ? cooldownMs : DEFAULT_GPU_CRASH_COOLDOWN_MS;
  const key = crashKey(input);
  const killed = !!(input && input.killed === true);
  st.count++;

  const inWindow = now >= 0 && st.lastSeen >= 0 && (now - st.lastSeen) < cool && st.lastKey === key;
  if (inWindow) {
    st.suppressed++;
    return {
      action: ACTION_SUPPRESS, key, killed, cooldownMs: cool,
      count: st.count, suppressed: st.suppressed,
    };
  }

  st.lastSeen = now >= 0 ? now : -1;
  st.lastKey = key;
  return {
    action: ACTION_RECORD, key, killed,
    detail: killed ? 'GPU 进程被系统终止' : 'GPU 进程崩溃，已尝试自动恢复',
    cooldownMs: cool, count: st.count, suppressed: st.suppressed,
  };
}

// decideAccessibilityChange 归一无障碍支持变化。
// app 事件第二参为布尔 enabled；非布尔按未知处理（不记录），返回 shouldRecord。
// 只在“开启”时提示留痕（环境渲染路径发生变化）；关闭只更新状态不告警。
function decideAccessibilityChange(enabled) {
  if (enabled !== true && enabled !== false) {
    return { known: false, enabled: false, shouldRecord: false, detail: '' };
  }
  return {
    known: true,
    enabled,
    shouldRecord: enabled === true,
    detail: enabled ? '系统无障碍 / 读屏支持被打开，渲染路径已切换' : '系统无障碍支持已关闭',
  };
}

module.exports = {
  ACTION_RECORD,
  ACTION_SUPPRESS,
  DEFAULT_GPU_CRASH_COOLDOWN_MS,
  MAX_GPU_FIELD_CHARS,
  GPU_BOOLEAN_FIELDS,
  GPU_STRING_FIELDS,
  clampField,
  sanitizeGPUInfo,
  createCrashState,
  crashKey,
  decideGPUCrash,
  decideAccessibilityChange,
};
