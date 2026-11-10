'use strict';

const {
  MAX_ORDER_IDS,
  MAX_ORDER_ID_LEN,
  REJECT_NOT_ARRAY,
  REJECT_BAD_ID,
  hasControlChar,
  isValidOrderId,
  sanitizeOrderIds,
} = require('./taborderconst');
const { longestStableSet, diffOrder, isSameOrder } = require('./taborderdiffset');

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
