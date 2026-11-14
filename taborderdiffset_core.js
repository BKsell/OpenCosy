'use strict';

const { MAX_ORDER_IDS, sanitizeOrderIds } = require('./taborderconst_core');

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
 *   moves:Array<{id:string, afterId:(string|null)}>,
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

module.exports = { longestStableSet, diffOrder, isSameOrder };
