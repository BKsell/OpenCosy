'use strict';

// taskmanager.js —— 浏览器任务管理器的纯数据内核（无 Electron 依赖、无副作用、无正则）。
//
// 数据来源是主进程 app.getAppMetrics() 返回的 ProcessMetric[]。Electron 文档里：
//   metric.type             进程类型字符串：'Browser' / 'Tab' / 'Renderer' / 'GPU' /
//                           'Utility' / 'Zygote' / 'Sandbox helper' 等；
//   metric.memory.private   进程私有内存（KB），最贴近“这进程独占多少内存”；
//   metric.memory.residentSet 常驻内存（KB），没有 private 时兜底；
//   metric.cpu.percentCPUUsage 是“距上一次 getAppMetrics 调用”的 CPU 占用百分比均值，
//                           因此 UI 必须定时轮询而不是只取一次；
//   metric.pid + creationTime 唯一标识一个进程（pid 会复用）。
//
// 本文件只做归类 / 取值 / 汇总，不触碰任何 Electron API，方便在 node --test 下纯测；
// 拿到原始 metrics、以及“渲染进程 pid -> 标签”映射后，渲染层据此渲染表格。

// 进程类别 key：i18n 文案留给渲染层，内核只给稳定的英文 key。
const PROCESS_KIND = Object.freeze({
  BROWSER: 'browser',
  TAB: 'tab',
  GPU: 'gpu',
  UTILITY: 'utility',
  OTHER: 'other',
});

// classifyType 把 Electron 五花八门的 type 字符串归一到有限类别。
// 现代 Chromium 站点进程是 'Tab'，老版本 / 非站点的渲染进程是 'Renderer'，两者都按标签类对待。
function classifyType(type) {
  const t = typeof type === 'string' ? type.toLowerCase() : '';
  if (t === 'browser') return PROCESS_KIND.BROWSER;
  if (t === 'tab' || t === 'renderer') return PROCESS_KIND.TAB;
  if (t === 'gpu' || t === 'gpu process') return PROCESS_KIND.GPU;
  if (t === 'utility' || t === 'zygote' || t === 'sandbox helper' || t === 'crashpad') {
    return PROCESS_KIND.UTILITY;
  }
  return PROCESS_KIND.OTHER;
}

// memoryKB 取进程内存占用（KB）。优先私有内存，缺失时回退常驻集，都没有按 0 处理；
// 非有限值（脏数据）也归零，避免汇总出 NaN。
function memoryKB(metric) {
  const mem = metric && metric.memory ? metric.memory : null;
  let value = 0;
  if (mem && Number.isFinite(mem.private) && mem.private > 0) {
    value = mem.private;
  } else if (mem && Number.isFinite(mem.residentSet) && mem.residentSet > 0) {
    value = mem.residentSet;
  }
  return Number.isFinite(value) && value > 0 ? Math.round(value) : 0;
}

// cpuPercent 取“距上次采样”的 CPU 占用百分比，夹紧到 [0,100]；脏数据归零。
function cpuPercent(metric) {
  const cpu = metric && metric.cpu ? metric.cpu : null;
  const raw = cpu && Number.isFinite(cpu.percentCPUUsage) ? cpu.percentCPUUsage : 0;
  if (raw <= 0) return 0;
  if (raw >= 100) return 100;
  return Math.round(raw * 10) / 10;
}

// formatMemoryKB 把 KB 渲染成人类可读体积：<1MB 用 KB，<1GB 用 MB（1 位小数），再大用 GB。
function formatMemoryKB(kb) {
  const value = Number.isFinite(kb) && kb > 0 ? kb : 0;
  if (value < 1024) return `${Math.round(value)} KB`;
  const mb = value / 1024;
  if (mb < 1024) return `${Math.round(mb * 10) / 10} MB`;
  const gb = mb / 1024;
  return `${Math.round(gb * 100) / 100} GB`;
}

// summarizeProcesses 把原始 metrics + 标签映射归并成 UI 行。
//   metrics   : app.getAppMetrics() 原样数组；
//   tabByPid  : Map<number, { id:string, title: string, index: number }>，由主进程用
//               tab.view.webContents.getOSProcessId() 关联得到。
// 返回 { total:{count,memoryKB,cpu}, byKind:[...], rows:[...] }，rows 按内存降序
// （内存相同按 pid 升序，保证渲染确定性）。只有能关联到具体标签的进程才允许“结束”
// （closable），结束动作由主进程按稳定 id 走现有 closeTab，绝不在内核 / 渲染层直接 kill pid。
function summarizeProcesses(metrics, tabByPid) {
  const list = Array.isArray(metrics) ? metrics : [];
  const tabMap = tabByPid instanceof Map ? tabByPid : new Map();
  const rows = [];
  let totalMemory = 0;
  let totalCpu = 0;

  for (const metric of list) {
    if (!metric || !Number.isFinite(metric.pid)) continue;
    const kind = classifyType(metric.type);
    const mem = memoryKB(metric);
    const cpu = cpuPercent(metric);
    const tab = tabMap.get(metric.pid);
    const isTab = kind === PROCESS_KIND.TAB && Boolean(tab);
    totalMemory += mem;
    totalCpu += cpu;
    rows.push({
      pid: metric.pid,
      kind,
      type: typeof metric.type === 'string' ? metric.type : '',
      name: typeof metric.name === 'string' ? metric.name : '',
      title: tab ? tab.title : '',
      tabId: tab && tab.id != null ? String(tab.id) : '',
      tabIndex: tab ? tab.index : -1,
      isTab,
      closable: isTab && !!tab.id && Number.isInteger(tab.index) && tab.index >= 0,
      memoryKB: mem,
      cpu,
    });
  }

  rows.sort((a, b) => {
    if (b.memoryKB !== a.memoryKB) return b.memoryKB - a.memoryKB;
    return a.pid - b.pid;
  });

  return {
    total: {
      count: rows.length,
      memoryKB: totalMemory,
      cpu: Math.round(totalCpu * 10) / 10,
    },
    byKind: aggregateByKind(rows),
    rows,
  };
}

// aggregateByKind 把归并后的行按进程类别聚合成数量/内存/CPU 小计，
// 返回按内存降序（内存相同比数量，再比 kind 字典序）的数组，供顶部“分类占用”卡片使用。
// 传入空表 / 非数组都返回 []，不抛错。
function aggregateByKind(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const validKinds = Object.values(PROCESS_KIND);
  const acc = new Map();

  for (const row of list) {
    if (!row || !validKinds.includes(row.kind)) continue;
    let item = acc.get(row.kind);
    if (!item) {
      item = { kind: row.kind, count: 0, memoryKB: 0, cpu: 0 };
      acc.set(row.kind, item);
    }
    item.count += 1;
    item.memoryKB += Number.isFinite(row.memoryKB) ? row.memoryKB : 0;
    item.cpu += Number.isFinite(row.cpu) ? row.cpu : 0;
  }

  return Array.from(acc.values())
    .map(item => ({
      kind: item.kind,
      count: item.count,
      memoryKB: item.memoryKB,
      cpu: Math.round(item.cpu * 10) / 10,
    }))
    .sort((a, b) => {
      if (b.memoryKB !== a.memoryKB) return b.memoryKB - a.memoryKB;
      if (b.count !== a.count) return b.count - a.count;
      if (a.kind === b.kind) return 0;
      return a.kind < b.kind ? -1 : 1;
    });
}

module.exports = {
  PROCESS_KIND,
  classifyType,
  memoryKB,
  cpuPercent,
  formatMemoryKB,
  summarizeProcesses,
  aggregateByKind,
};
