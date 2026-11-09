'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  PROCESS_KIND,
  classifyType,
  memoryKB,
  cpuPercent,
  formatMemoryKB,
  summarizeProcesses,
  aggregateByKind,
} = require('./taskmanager');

function metric(over) {
  return Object.assign({
    pid: 1,
    type: 'Tab',
    memory: { private: 1024, residentSet: 2048 },
    cpu: { percentCPUUsage: 12.34 },
  }, over);
}

test('classifyType 归一 Electron 各进程类型字符串', () => {
  assert.strictEqual(classifyType('Browser'), PROCESS_KIND.BROWSER);
  assert.strictEqual(classifyType('Tab'), PROCESS_KIND.TAB);
  assert.strictEqual(classifyType('Renderer'), PROCESS_KIND.TAB);
  assert.strictEqual(classifyType('GPU Process'), PROCESS_KIND.GPU);
  for (const t of ['Utility', 'Zygote', 'Sandbox helper', 'Crashpad']) {
    assert.strictEqual(classifyType(t), PROCESS_KIND.UTILITY);
  }
  assert.strictEqual(classifyType('Something Else'), PROCESS_KIND.OTHER);
});

test('classifyType 大小写与脏入参安全', () => {
  assert.strictEqual(classifyType('  BROWSER'.trim()), PROCESS_KIND.BROWSER);
  assert.strictEqual(classifyType(undefined), PROCESS_KIND.OTHER);
  assert.strictEqual(classifyType(null), PROCESS_KIND.OTHER);
  assert.strictEqual(classifyType(42), PROCESS_KIND.OTHER);
});

test('memoryKB 优先 private，回退 residentSet，脏数据归零', () => {
  assert.strictEqual(memoryKB(metric({ memory: { private: 300, residentSet: 900 } })), 300);
  assert.strictEqual(memoryKB(metric({ memory: { residentSet: 900 } })), 900);
  assert.strictEqual(memoryKB(metric({ memory: {} })), 0);
  assert.strictEqual(memoryKB(metric({ memory: null })), 0);
  assert.strictEqual(memoryKB(null), 0);
  assert.strictEqual(memoryKB(metric({ memory: { private: NaN } })), 0);
  assert.strictEqual(memoryKB(metric({ memory: { private: -5 } })), 0);
  assert.strictEqual(memoryKB(metric({ memory: { private: 12.6 } })), 13);
});

test('cpuPercent 夹紧 [0,100]，保留一位小数，脏数据归零', () => {
  assert.strictEqual(cpuPercent(metric({ cpu: { percentCPUUsage: 12.34 } })), 12.3);
  assert.strictEqual(cpuPercent(metric({ cpu: { percentCPUUsage: 0 } })), 0);
  assert.strictEqual(cpuPercent(metric({ cpu: { percentCPUUsage: -8 } })), 0);
  assert.strictEqual(cpuPercent(metric({ cpu: { percentCPUUsage: 180 } })), 100);
  assert.strictEqual(cpuPercent(metric({ cpu: null })), 0);
  assert.strictEqual(cpuPercent(null), 0);
});

test('formatMemoryKB 按 KB/MB/GB 分级', () => {
  assert.strictEqual(formatMemoryKB(0), '0 KB');
  assert.strictEqual(formatMemoryKB(512), '512 KB');
  assert.strictEqual(formatMemoryKB(2048), '2 MB');
  assert.strictEqual(formatMemoryKB(1024 * 1536), '1.5 GB');
  assert.strictEqual(formatMemoryKB(NaN), '0 KB');
  assert.strictEqual(formatMemoryKB(-10), '0 KB');
});

test('summarizeProcesses 跳过无 pid 项，内存降序、同内存 pid 升序', () => {
  const z = { cpu: { percentCPUUsage: 0 } };
  const metrics = [
    { pid: 10, type: 'Tab', memory: { private: 100 }, cpu: z.cpu },
    { pid: 20, type: 'Browser', memory: { private: 500 }, cpu: z.cpu },
    { pid: 5, type: 'Tab', memory: { private: 500 }, cpu: z.cpu },
    { type: 'GPU', memory: { private: 10 }, cpu: z.cpu },  // 无 pid，跳过
    { pid: NaN, type: 'Tab', memory: { private: 9 }, cpu: z.cpu }, // 非法 pid，跳过
  ];
  const result = summarizeProcesses(metrics, new Map());
  assert.strictEqual(result.rows.length, 3);
  assert.deepStrictEqual(result.rows.map(r => r.pid), [5, 20, 10]);
});

test('summarizeProcesses 仅关联标签的渲染进程 closable，结束动作带 index', () => {
  const metrics = [
    metric({ pid: 100, type: 'Tab' }),
    metric({ pid: 200, type: 'Tab' }),
    metric({ pid: 1, type: 'Browser' }),
  ];
  const tabs = new Map([[100, { id: 'tab100', title: '示例页', index: 3 }]]);
  const result = summarizeProcesses(metrics, tabs);
  const byPid = new Map(result.rows.map(r => [r.pid, r]));
  assert.strictEqual(byPid.get(100).closable, true);
  assert.strictEqual(byPid.get(100).tabId, 'tab100');
  assert.strictEqual(byPid.get(100).tabIndex, 3);
  assert.strictEqual(byPid.get(100).title, '示例页');
  assert.strictEqual(byPid.get(200).closable, false); // 渲染进程但无标签映射
  assert.strictEqual(byPid.get(1).closable, false);  // 浏览器主进程永不 closable
});

test('summarizeProcesses 总计与脏入参安全', () => {
  const result = summarizeProcesses(null, null);
  assert.strictEqual(result.rows.length, 0);
  assert.deepStrictEqual(result.total, { count: 0, memoryKB: 0, cpu: 0 });
  assert.deepStrictEqual(result.byKind, []);
  const tabs = new Map([['not-a-number', { title: 'x', index: 0 }]]);
  const r2 = summarizeProcesses([metric({ pid: 7 })], tabs);
  assert.strictEqual(r2.rows[0].closable, false);
  // 映射到标签但缺少稳定 id：不允许结束，防止拿漂移的索引误关。
  const r3 = summarizeProcesses(
    [metric({ pid: 8, type: 'Tab' })],
    new Map([[8, { title: 'y', index: 1 }]]),
  );
  assert.strictEqual(r3.rows[0].closable, false);
  assert.strictEqual(r3.rows[0].tabId, '');
});

test('summarizeProcesses 输出 byKind 分类小计且与总计一致', () => {
  const metrics = [
    { pid: 1, type: 'Browser', memory: { private: 300 }, cpu: { percentCPUUsage: 1 } },
    { pid: 2, type: 'Tab', memory: { private: 900 }, cpu: { percentCPUUsage: 40 } },
    { pid: 3, type: 'Tab', memory: { private: 100 }, cpu: { percentCPUUsage: 0 } },
    { pid: 4, type: 'GPU', memory: { residentSet: 50 }, cpu: { percentCPUUsage: 2 } },
  ];
  const result = summarizeProcesses(metrics, new Map([[2, { title: 'a', index: 0 }]]));
  assert.deepStrictEqual(result.byKind.map(k => k.kind), [
    PROCESS_KIND.TAB, PROCESS_KIND.BROWSER, PROCESS_KIND.GPU,
  ]);
  const tab = result.byKind.find(k => k.kind === PROCESS_KIND.TAB);
  assert.deepStrictEqual(tab, { kind: PROCESS_KIND.TAB, count: 2, memoryKB: 1000, cpu: 40 });
  assert.strictEqual(result.byKind.reduce((s, k) => s + k.count, 0), result.total.count);
  assert.strictEqual(result.byKind.reduce((s, k) => s + k.memoryKB, 0), result.total.memoryKB);
});

test('aggregateByKind 独立聚合：数量/内存/CPU、降序、脏入参安全', () => {
  const rows = [
    { kind: PROCESS_KIND.GPU, memoryKB: 50, cpu: 2 },
    { kind: PROCESS_KIND.UTILITY, memoryKB: 50, cpu: 0 },
    { kind: PROCESS_KIND.TAB, memoryKB: 700, cpu: 30 },
    { kind: PROCESS_KIND.TAB, memoryKB: 300, cpu: 10 },
    { kind: 'bogus', memoryKB: 999, cpu: 99 },
    null,
  ];
  const out = aggregateByKind(rows);
  assert.deepStrictEqual(out.map(k => k.kind), [
    PROCESS_KIND.TAB, PROCESS_KIND.GPU, PROCESS_KIND.UTILITY,
  ]);
  assert.deepStrictEqual(out[0], { kind: PROCESS_KIND.TAB, count: 2, memoryKB: 1000, cpu: 40 });
  // 内存与数量都并列（各类各 1 个、同 10KB）时按 kind 字典序。
  const tie = aggregateByKind([
    { kind: PROCESS_KIND.UTILITY, memoryKB: 10, cpu: 0 },
    { kind: PROCESS_KIND.GPU, memoryKB: 10, cpu: 0 },
    { kind: PROCESS_KIND.OTHER, memoryKB: 10, cpu: 0 },
  ]);
  assert.deepStrictEqual(tie.map(k => k.kind), [
    PROCESS_KIND.GPU, PROCESS_KIND.OTHER, PROCESS_KIND.UTILITY,
  ]);
  // 内存并列但数量不同：数量多的排前（utility 2×10=20 压过 gpu 1×20=20 时，
  // 这里用同总量不同构成验证 count 次排序）。
  const countWins = aggregateByKind([
    { kind: PROCESS_KIND.UTILITY, memoryKB: 10, cpu: 0 },
    { kind: PROCESS_KIND.UTILITY, memoryKB: 10, cpu: 0 },
    { kind: PROCESS_KIND.GPU, memoryKB: 20, cpu: 0 },
  ]);
  assert.deepStrictEqual(countWins.map(k => k.kind), [PROCESS_KIND.UTILITY, PROCESS_KIND.GPU]);
  assert.deepStrictEqual(aggregateByKind(null), []);
  assert.deepStrictEqual(aggregateByKind([]), []);
});
