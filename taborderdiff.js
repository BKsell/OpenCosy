'use strict';

// taborderdiff.js —— 标签栏顺序差异（reorder diff）纯逻辑内核。
//
// 背景：
//   tabgroups.arrangeTabs 只负责“理想顺序应该长什么样”，输出一个标签 id 数组：
//   固定区在前、组内聚类、未分组垫后。但主进程 / 渲染层拿到这个目标序列后，不能简单
//   粗暴地把整个标签栏拆光重建——那会让每个 WebContentsView 重新挂载，丢滚动位置、
//   丢前进后退栈的呈现、闪烁且昂贵。真正需要的是一组“最小移动指令”：只把少数位置不
//   对的标签，插到正确的锚点之后；已经相对有序的标签一个都不动。
//
//   本模块就负责把“当前顺序 prev”与“目标顺序 next”归约成这样一组指令：
//     created —— 目标里有、当前没有的 id（新打开 / 新进入编排的标签），调用方负责新建
//                或把它纳入标签栏，随后按 afterId 归位；
//     removed —— 当前有、目标里没有的 id（已关闭 / 被固定区或分组剔除），仅上报，本
//                模块不下达关闭指令，关闭永远走既有 closeTab 路径；
//     moves   —— 两边都有、但相对位置需要调整的 id，按目标顺序给出 afterId 锚点；
//     stable  —— 两边都有且落在“最长递增子序列”上、无需移动的 id。
//
//   moves 用最长递增子序列（LIS）最小化：在目标顺序中、其在当前顺序里的下标已经严格
//   递增的最长那一截标签可以原地不动，其余共有标签才需要移动。指令数因此最少。
//
// 安全：
//   入参可能来自 IPC（渲染层上报的观察顺序）或磁盘清单。这里对每个 id 做类型 / 长度 /
//   控制字符校验、去重保序、总量截断；任何非字符串、空串、超长或含控制字符的条目都
//   丢弃，绝不把脏字符串回灌给主进程的移动 / 关闭逻辑，也防止被撑大的序列拖垮 LIS。
//   本模块是纯计算，不碰 DOM / Electron，不执行任何回调以外的副作用。

// ---- 上界与拒绝原因 ----
const MAX_ORDER_IDS = 500;  // 单窗口参与顺序编排的标签数硬上界，与标签栏实际容量对齐
const MAX_ORDER_ID_LEN = 128; // 单个标签 id 长度上界，与 pintabs / tabgroups 保持一致

const REJECT_NOT_ARRAY = 'not-array';
const REJECT_BAD_ID = 'bad-id';

// 与 tabgroups.sanitizeTabId 同一判定口径，但这里是批量、保序、去重、截断的版本，
// 独立实现以保持模块自包含（不反向依赖 tabgroups，便于单测与复用）。
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    // 0x00-0x1F 与 0x7F 为 ASCII 控制字符（含 \t \n \r 等），标签 id 不允许出现。
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isValidOrderId(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > MAX_ORDER_ID_LEN) return false;
  if (hasControlChar(value)) return false;
  return true;
}

/**
 * 把任意输入净化成“唯一、保序、有上界”的标签 id 数组。
 * 非法 / 重复条目静默丢弃（顺序编排对单个脏 id 的策略是跳过，而非整单拒绝）。
 * @param {*} raw
 * @param {number} [limit]
 * @returns {{ok:boolean,reason?:string,value:string[]}}
 */
function sanitizeOrderIds(raw, limit) {
  if (!Array.isArray(raw)) return { ok: false, reason: REJECT_NOT_ARRAY, value: [] };
  const max = Number.isInteger(limit) && limit > 0 ? limit : MAX_ORDER_IDS;
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (!isValidOrderId(item)) continue;
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
    if (out.length >= max) break;
  }
  return { ok: true, value: out };
}

/**
 * 在“目标顺序”中找出无需移动的最大标签集合。
 * 做法：取共有 id，按其在 next 中的先后排列，对应到 prev 中的下标，求该下标序列的
 * 严格递增最长子序列——LIS 上的标签彼此相对顺序在 prev/next 间一致，可原地不动。
 * 返回一个 Set，内容为“保持不动”的共有 id。
 * @param {string[]} prev 已净化的当前顺序
 * @param {string[]} next 已净化的目标顺序
 * @returns {Set<string>}
 */
function longestStableSet(prev, next) {
  const prevIndex = new Map();
  for (let i = 0; i < prev.length; i++) {
    if (!prevIndex.has(prev[i])) prevIndex.set(prev[i], i);
  }
  // 共有标签按 next 顺序排列时对应的 prev 下标。
  const seqIds = [];
  const seqIdx = [];
  for (const id of next) {
    if (prevIndex.has(id)) {
      seqIds.push(id);
      seqIdx.push(prevIndex.get(id));
    }
  }

  // 经典 O(n log n) LIS：tails[k] 记录长度为 k+1 的递增子序列的最小结尾下标，
  // parent 链用于最后回溯具体成员。要求严格递增（相等下标只会在去重后出现 0 次）。
  const n = seqIdx.length;
  const tails = [];
  const tailId = [];
  const parent = new Array(n).fill(-1);

  for (let i = 0; i < n; i++) {
    const x = seqIdx[i];
    let lo = 0;
    let hi = tails.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (tails[mid] < x) lo = mid + 1;
      else hi = mid;
    }
    tails[lo] = x;
    tailId[lo] = i;
    if (lo > 0) parent[i] = tailId[lo - 1];
  }

  const stable = new Set();
  if (tailId.length === 0) return stable;
  let k = tailId[tailId.length - 1];
  while (k !== -1) {
    stable.add(seqIds[k]);
    k = parent[k];
  }
  return stable;
}

/**
 * 计算 prev -> next 的最小重排计划。
 *
 * moves 的顺序与锚点：按 next 从左到右处理所有“需要定位”的共有标签（即不在 stable
 * 集合里的），每条指令 { id, afterId } 表示“把 id 移到 afterId 之后”；afterId 为
 * null 表示放到最前。afterId 取该 id 在 next 中的前一个元素——调用方按返回顺序逐条
 * insertAfter 即可，因为轮到某条时它的锚点必然已就位（要么原本稳定，要么已被前一条
 * 指令归位）。
 *
 * @param {string[]} rawPrev 当前顺序（未净化亦可，内部会净化）
 * @param {string[]} rawNext 目标顺序
 * @returns {{
 *   ok:boolean, reason?:string,
 *   prev:string[], next:string[],
 *   created:string[], removed:string[], stable:string[],
 *   moves:Array<{{id:string, afterId:(string|null)}}>,
 *   unchanged:boolean
 * }}
 */
function diffOrder(rawPrev, rawNext) {
  const p = sanitizeOrderIds(rawPrev);
  const q = sanitizeOrderIds(rawNext);
  if (!p.ok) return fail(p.reason);
  if (!q.ok) return fail(q.reason);

  const prev = p.value;
  const next = q.value;
  const prevSet = new Set(prev);
  const nextSet = new Set(next);

  const created = [];
  const removed = [];
  for (const id of next) {
    if (!prevSet.has(id)) created.push(id);
  }
  for (const id of prev) {
    if (!nextSet.has(id)) removed.push(id);
  }

  const stableSet = longestStableSet(prev, next);
  const stable = [];
  const moves = [];
  for (let i = 0; i < next.length; i++) {
    const id = next[i];
    if (!prevSet.has(id)) continue; // 新标签不算“移动”，其归位由 created 处理
    if (stableSet.has(id)) {
      stable.push(id);
      continue;
    }
    // 前一个目标元素作为锚点；位于首位时 afterId=null。
    const afterId = i > 0 ? next[i - 1] : null;
    moves.push({ id, afterId });
  }

  return {
    ok: true,
    prev,
    next,
    created,
    removed,
    stable,
    moves,
    unchanged: created.length === 0 && removed.length === 0 && moves.length === 0,
  };
}

function fail(reason) {
  return {
    ok: false,
    reason,
    prev: [],
    next: [],
    created: [],
    removed: [],
    stable: [],
    moves: [],
    unchanged: false,
  };
}

/**
 * 便捷判定：目标顺序相对当前是否已经完全一致（忽略两侧各自的脏 id 后）。
 * @param {string[]} rawPrev
 * @param {string[]} rawNext
 * @returns {boolean}
 */
function isSameOrder(rawPrev, rawNext) {
  const d = diffOrder(rawPrev, rawNext);
  return d.ok && d.unchanged;
}

module.exports = {
  MAX_ORDER_IDS,
  MAX_ORDER_ID_LEN,
  REJECT_NOT_ARRAY,
  REJECT_BAD_ID,
  hasControlChar,
  isValidOrderId,
  sanitizeOrderIds,
  longestStableSet,
  diffOrder,
  isSameOrder,
};
