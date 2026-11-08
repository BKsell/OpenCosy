'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const tg = require('./tabgroups');
const {
  MAX_GROUPS,
  MAX_TABS_PER_GROUP,
  MAX_GROUP_TITLE_LEN,
  GROUP_COLORS,
  FALLBACK_GROUP_COLOR,
  REJECT_NOT_STRING,
  REJECT_NOT_ARRAY,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  REJECT_LIMIT,
  REJECT_NOT_FOUND,
  REJECT_PINNED,
  REJECT_DUPLICATE,
  REJECT_EMPTY,
  hasControlChar,
  makeGroupId,
  sanitizeGroupId,
  sanitizeTabId,
  sanitizeGroupTitle,
  sanitizeGroupColor,
  sanitizeTabIdList,
  sanitizeStoredGroups,
  rehydrateGroupsByTabs,
  arrangeTabs,
  TabGroupModel,
} = tg;

// ---- 基础校验 ----

test('hasControlChar 识别 ASCII 控制字符', () => {
  assert.equal(hasControlChar('普通标题'), false);
  assert.equal(hasControlChar('work-tabs'), false);
  assert.equal(hasControlChar('a\nb'), true);
  assert.equal(hasControlChar('x\x00y'), true);
  assert.equal(hasControlChar('z\x7f'), true);
});

test('sanitizeGroupId 规则', () => {
  assert.equal(sanitizeGroupId('g1').ok, true);
  assert.equal(sanitizeGroupId('').ok, false);
  assert.equal(sanitizeGroupId(123).reason, REJECT_NOT_STRING);
  assert.equal(sanitizeGroupId(null).reason, REJECT_NOT_STRING);
  assert.equal(sanitizeGroupId('a\rb').reason, REJECT_CONTROL);
  assert.equal(sanitizeGroupId('x'.repeat(65)).reason, REJECT_TOO_LONG);
  assert.equal(sanitizeGroupId('x'.repeat(64)).ok, true);
});

test('sanitizeTabId 规则与 pintabs 对齐', () => {
  assert.equal(sanitizeTabId('tab-1').ok, true);
  assert.equal(sanitizeTabId('').ok, false);
  assert.equal(sanitizeTabId(undefined).reason, REJECT_NOT_STRING);
  assert.equal(sanitizeTabId('a\tb').reason, REJECT_CONTROL);
  assert.equal(sanitizeTabId('y'.repeat(129)).reason, REJECT_TOO_LONG);
});

test('sanitizeGroupTitle 裁剪空白、允许空串、拒绝控制字符与超长', () => {
  assert.equal(sanitizeGroupTitle('  调研  ').value, '调研');
  assert.equal(sanitizeGroupTitle('').value, '');
  assert.equal(sanitizeGroupTitle(42).reason, REJECT_NOT_STRING);
  assert.equal(sanitizeGroupTitle('a\nb').reason, REJECT_CONTROL);
  assert.equal(sanitizeGroupTitle('z'.repeat(MAX_GROUP_TITLE_LEN + 1)).reason, REJECT_TOO_LONG);
});

test('sanitizeGroupColor 白名单与回退', () => {
  for (const c of GROUP_COLORS) assert.equal(sanitizeGroupColor(c).value, c);
  assert.equal(sanitizeGroupColor('not-a-color').value, FALLBACK_GROUP_COLOR);
  assert.equal(sanitizeGroupColor(undefined).value, FALLBACK_GROUP_COLOR);
  assert.equal(sanitizeGroupColor(null).value, FALLBACK_GROUP_COLOR);
});

test('sanitizeTabIdList 去非法 / 去重 / 保序 / 截断', () => {
  const r = sanitizeTabIdList(['a', 'b', 'a', 1, '', 'c']);
  assert.deepEqual(r.value, ['a', 'b', 'c']);
  assert.equal(sanitizeTabIdList('x').ok, false);
  assert.equal(sanitizeTabIdList(null).reason, REJECT_NOT_ARRAY);
  const many = Array.from({ length: MAX_TABS_PER_GROUP + 5 }, (_, i) => 't' + i);
  assert.equal(sanitizeTabIdList(many).value.length, MAX_TABS_PER_GROUP);
});

test('makeGroupId 产出安全、唯一的短 id', () => {
  const a = makeGroupId(1700000000000);
  const b = makeGroupId(1700000000000);
  assert.match(a, /^g[0-9a-z]+-[0-9a-z]+$/);
  assert.notEqual(a, b);
  assert.equal(sanitizeGroupId(makeGroupId()).ok, true);
});

// ---- 模型：建组 / 增删 / 移动 ----

test('createGroup 基础建组与反向索引', () => {
  const m = new TabGroupModel();
  const r = m.createGroup({ title: '工作', color: 'blue', tabIds: ['t1', 't2'] });
  assert.equal(r.ok, true);
  assert.equal(m.groupCount(), 1);
  assert.equal(m.groupOf('t1'), r.group.id);
  assert.deepEqual(m.tabsInGroup(r.group.id), ['t1', 't2']);
  assert.deepEqual(m.groupedTabIds(), ['t1', 't2']);
});

test('createGroup 默认拒绝空选择，allowEmpty 可建空组', () => {
  const m = new TabGroupModel();
  assert.equal(m.createGroup({ tabIds: [] }).reason, REJECT_EMPTY);
  const r = m.createGroup({ tabIds: [], allowEmpty: true });
  assert.equal(r.ok, true);
  assert.equal(m.groupCount(), 1);
});

test('固定标签不能入组（建组与追加都剔除）', () => {
  const m = new TabGroupModel();
  const pinned = new Set(['p1']);
  const r = m.createGroup({ title: 'g', tabIds: ['a', 'p1'] }, id => pinned.has(id));
  assert.equal(r.ok, true);
  assert.deepEqual(r.tabIds, ['a']);
  assert.equal(m.groupOf('p1'), null);
  const add = m.addTabs(r.group.id, ['p1', 'b'], id => pinned.has(id));
  assert.deepEqual(add.added, ['b']);
  assert.deepEqual(add.skippedPinned, ['p1']);
});

test('createGroup 达分组上界拒绝', () => {
  const m = new TabGroupModel();
  for (let i = 0; i < MAX_GROUPS; i++) {
    const r = m.createGroup({ tabIds: ['t' + i], allowEmpty: true });
    assert.equal(r.ok, true);
  }
  assert.equal(m.createGroup({ tabIds: ['overflow'] }).reason, REJECT_LIMIT);
});

test('addTabs 跨组移动语义与单组上界', () => {
  const m = new TabGroupModel();
  const g1 = m.createGroup({ tabIds: ['a', 'b'] }).group.id;
  const g2 = m.createGroup({ tabIds: ['c'] }).group.id;
  const r = m.addTabs(g2, ['a', 'd']);
  assert.deepEqual(r.added, ['a', 'd']);
  assert.deepEqual(m.tabsInGroup(g1), ['b']);
  assert.deepEqual(m.tabsInGroup(g2), ['c', 'a', 'd']);
  // 幂等：重复加入不产生重复
  assert.deepEqual(m.addTabs(g2, ['c', 'a']).added, []);
  assert.equal(m.tabsInGroup(g2).length, 3);
});

test('removeTabs / moveTab 到 null', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ tabIds: ['a', 'b'] }).group.id;
  assert.deepEqual(m.removeTabs(['a']).removed, ['a']);
  assert.equal(m.isGrouped('a'), false);
  assert.deepEqual(m.tabsInGroup(gid), ['b']);
  const gid2 = m.createGroup({ tabIds: ['c'] }).group.id;
  const mv = m.moveTab('b', gid2);
  assert.equal(mv.ok, true);
  assert.equal(m.groupOf('b'), gid2);
  const out = m.moveTab('c', null);
  assert.equal(out.movedTo, null);
  assert.equal(m.isGrouped('c'), false);
});

test('moveTab 固定标签拒绝、目标组不存在拒绝', () => {
  const m = new TabGroupModel();
  const pinned = new Set(['p']);
  assert.equal(m.moveTab('p', 'gx', id => pinned.has(id)).reason, REJECT_PINNED);
  assert.equal(m.moveTab('a', 'missing').reason, REJECT_NOT_FOUND);
});

test('rename / color / collapsed 属性更新', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ tabIds: ['a'] }).group.id;
  assert.equal(m.renameGroup(gid, '  新名字 ').group.title, '新名字');
  assert.equal(m.setGroupColor(gid, 'red').group.color, 'red');
  assert.equal(m.setGroupCollapsed(gid, true).group.collapsed, true);
  assert.equal(m.renameGroup('nope', 'x').reason, REJECT_NOT_FOUND);
  assert.equal(m.setGroupColor(gid, 'weird').group.color, FALLBACK_GROUP_COLOR);
});

test('moveGroup 调整分组顺序（含移到末尾与前移）', () => {
  const m = new TabGroupModel();
  const a = m.createGroup({ tabIds: ['1'], allowEmpty: true }).group.id;
  const b = m.createGroup({ tabIds: ['2'], allowEmpty: true }).group.id;
  const c = m.createGroup({ tabIds: ['3'], allowEmpty: true }).group.id;
  assert.deepEqual(m.orderedGroupIds(), [a, b, c]);
  assert.deepEqual(m.moveGroup(a, c).order, [b, a, c]);
  assert.deepEqual(m.moveGroup(c, null).order, [b, a, c]); // c 已在末尾
  assert.deepEqual(m.moveGroup(c, b).order, [c, b, a]);
  assert.equal(m.moveGroup('x', null).reason, REJECT_NOT_FOUND);
});

test('dissolveGroup 释放标签但不关闭', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ tabIds: ['a', 'b'] }).group.id;
  const r = m.dissolveGroup(gid);
  assert.deepEqual(r.freedTabs.sort(), ['a', 'b']);
  assert.equal(m.hasGroup(gid), false);
  assert.equal(m.isGrouped('a'), false);
  assert.equal(m.dissolveGroup(gid).reason, REJECT_NOT_FOUND);
});

test('onTabClosed 清理成员，空组默认自动解散', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ tabIds: ['a', 'b'] }).group.id;
  const r1 = m.onTabClosed('a');
  assert.equal(r1.removed, true);
  assert.equal(r1.dissolved, false);
  assert.equal(m.hasGroup(gid), true);
  const r2 = m.onTabClosed('b');
  assert.equal(r2.dissolved, true);
  assert.equal(m.hasGroup(gid), false);
  // 未入组标签关闭无副作用
  assert.equal(m.onTabClosed('zz').removed, false);
});

test('onTabClosed removeEmpty=false 时保留空组', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ tabIds: ['a'] }).group.id;
  const r = m.onTabClosed('a', false);
  assert.equal(r.dissolved, false);
  assert.equal(m.hasGroup(gid), true);
  assert.deepEqual(m.tabsInGroup(gid), []);
});

// ---- 持久化净化 / 重水合 ----

test('sanitizeStoredGroups 顶层与字段净化', () => {
  assert.deepEqual(sanitizeStoredGroups('x'), []);
  assert.deepEqual(sanitizeStoredGroups(null), []);
  const raw = [
    { id: 'g1', title: ' 工作 ', color: 'blue', collapsed: true, tabIds: ['a', 'b'] },
    null,
    { id: '', title: 'bad', tabIds: ['x'] },                       // 非法 id
    { id: 'g2', title: 't', color: 'weird', tabIds: ['c', 'a'] }, // a 已在 g1
    { id: 'g3', title: 't', tabIds: [] },                          // 空组丢弃
    42,
  ];
  const out = sanitizeStoredGroups(raw);
  assert.equal(out.length, 2);
  assert.deepEqual(out[0], { id: 'g1', title: '工作', color: 'blue', collapsed: true, tabIds: ['a', 'b'] });
  assert.deepEqual(out[1], { id: 'g2', title: 't', color: FALLBACK_GROUP_COLOR, collapsed: false, tabIds: ['c'] });
});

test('sanitizeStoredGroups 去重组 id 与数量截断', () => {
  const raw = [];
  for (let i = 0; i < MAX_GROUPS + 3; i++) {
    raw.push({ id: 'g' + i, title: '', tabIds: ['t' + i] });
  }
  const out = sanitizeStoredGroups(raw);
  assert.equal(out.length, MAX_GROUPS);
  const dup = sanitizeStoredGroups([
    { id: 'same', tabIds: ['a'] },
    { id: 'same', tabIds: ['b'] },
  ]);
  assert.equal(dup.length, 1);
});

test('rehydrateGroupsByTabs 剔除已关闭与已固定标签，丢弃空组', () => {
  const stored = [
    { id: 'g1', title: 'g1', color: 'blue', tabIds: ['keep', 'gone', 'pinned'] },
    { id: 'g2', title: 'g2', color: 'red', tabIds: ['allgone'] },
  ];
  const current = [
    { id: 'keep' },
    { id: 'pinned', pinned: true },
    { id: 'other' },
  ];
  const out = rehydrateGroupsByTabs(stored, current);
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'g1');
  assert.deepEqual(out[0].tabIds, ['keep']);
});

test('loadStored + serialize 往返', () => {
  const stored = sanitizeStoredGroups([
    { id: 'g1', title: 'A', color: 'green', tabIds: ['a', 'b'] },
    { id: 'g2', title: 'B', color: 'red', tabIds: ['c'] },
  ]);
  const m = new TabGroupModel();
  m.loadStored(stored);
  assert.equal(m.groupCount(), 2);
  assert.deepEqual(m.groupedTabIds(), ['a', 'b', 'c']);
  const again = new TabGroupModel();
  again.loadStored(m.serialize());
  assert.deepEqual(again.serialize(), m.serialize());
});

// ---- 编排 ----

test('arrangeTabs 固定区 + 分组聚类 + 未分组', () => {
  const m = new TabGroupModel();
  // 当前标签栏乱序：u(未分组) p(固定) g2成员 g1成员 ...
  const g1 = m.createGroup({ id: 'G1', title: 'g1', color: 'blue', tabIds: ['a1', 'a2'] }).group.id;
  const g2 = m.createGroup({ id: 'G2', title: 'g2', color: 'red', tabIds: ['b1'] }).group.id;
  const tabs = [
    { id: 'u1' },
    { id: 'pin2', pinned: true },
    { id: 'b1' },
    { id: 'u2' },
    { id: 'pin1', pinned: true },
    { id: 'a2' },
    { id: 'a1' },
  ];
  const order = arrangeTabs(tabs, m, { pinnedIdOrder: ['pin1', 'pin2'] });
  // 固定在前（按 pin 顺序），随后按分组顺序 G1(a1,a2) G2(b1) 聚类，未分组保序垫后
  assert.deepEqual(order, ['pin1', 'pin2', 'a1', 'a2', 'b1', 'u1', 'u2']);
});

test('arrangeTabs 折叠不影响顺序、已消失标签不输出', () => {
  const m = new TabGroupModel();
  const gid = m.createGroup({ id: 'G', tabIds: ['a', 'b'] }).group.id;
  m.setGroupCollapsed(gid, true);
  const order = arrangeTabs([{ id: 'b' }, { id: 'x' }, { id: 'a' }], m, {});
  assert.deepEqual(order, ['a', 'b', 'x']);
});

test('arrangeTabs 去重并忽略非字符串 id', () => {
  const m = new TabGroupModel();
  m.createGroup({ id: 'G', tabIds: ['a'] });
  const order = arrangeTabs([{ id: 'a' }, { id: 'a' }, { id: 1 }, null, { id: 'z' }], m, {});
  assert.deepEqual(order, ['a', 'z']);
});
