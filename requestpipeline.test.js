'use strict';

// requestpipeline.test.js —— 统一请求决策内核的表驱动测试。
// 用最小桩件验证决策顺序与短路语义（ping > tracker > pna > mixed > 追踪参数 >
// 钓鱼横幅 > https-only > allow），以及 redirect 不计数、cancel/allow 才计数。

const test = require('node:test');
const assert = require('node:assert');

const {
  DECISION_CANCEL,
  DECISION_REDIRECT,
  DECISION_ALLOW,
  isHttpUrl,
  decideRequest,
  applyPipeline,
} = require('./requestpipeline');

// 空守卫：默认全部“不命中”，便于按需只打开某一支。
function baseDeps(overrides) {
  const calls = [];
  const deps = {
    flags: {
      blockHyperlinkPing: true,
      blockLocalNetworkAccess: true,
      httpsOnlyEnabled: false,
    },
    guards: {
      hostOf: (u) => { try { return new URL(u).hostname; } catch { return ''; } },
      isHyperlinkPing: () => false,
      isTrackerRequest: () => false,
      evaluatePnaRequest: () => ({ block: false }),
      classifyMixedContent: () => ({ action: 'allow' }),
      stripTrackingFromUrl: () => '',
      analyzeHostForSpoof: () => null,
      analyzeBrand: () => null,
      analyzePhish: () => null,
      isPrivateNetworkHost: () => false,
    },
    record: {
      fpHit: (...a) => calls.push(['fpHit', ...a]),
      securityEvent: (...a) => calls.push(['securityEvent', ...a]),
      blockedTracker: (...a) => calls.push(['blockedTracker', ...a]),
      pnaBlock: () => calls.push(['pnaBlock']),
      brandSpoof: (...a) => calls.push(['brandSpoof', ...a]),
    },
    notify: { sendToRenderer: (...a) => calls.push(['sendToRenderer', ...a]) },
  };
  return { calls, deps: Object.assign({}, deps, overrides || {}) };
}

test('isHttpUrl 只接受 http/https 字符串', () => {
  assert.equal(isHttpUrl('http://a.test'), true);
  assert.equal(isHttpUrl('https://a.test'), true);
  assert.equal(isHttpUrl('file:///c:/x'), false);
  assert.equal(isHttpUrl('cosy://newtab'), false);
  assert.equal(isHttpUrl(''), false);
  assert.equal(isHttpUrl(null), false);
});

test('无任何命中时放行 http 与非 http 请求', () => {
  const { deps } = baseDeps();
  assert.deepEqual(decideRequest(deps, { url: 'https://a.test/x', resourceType: 'subFrame' }),
    { type: DECISION_ALLOW });
  assert.deepEqual(decideRequest(deps, { url: 'cosy://newtab', resourceType: 'mainFrame' }),
    { type: DECISION_ALLOW });
});

test('ping 命中优先于 tracker，直接取消', () => {
  const { deps, calls } = baseDeps();
  deps.guards.isHyperlinkPing = () => true;
  deps.guards.isTrackerRequest = () => { throw new Error('不应继续评估 tracker'); };
  const r = decideRequest(deps, { url: 'https://a.test/p', resourceType: 'ping' });
  assert.equal(r.type, DECISION_CANCEL);
  assert.equal(r.reason, 'ping');
  assert.ok(calls.some((c) => c[0] === 'fpHit'));
});

test('tracker 子资源被取消', () => {
  const { deps, calls } = baseDeps();
  deps.guards.isTrackerRequest = () => true;
  const r = decideRequest(deps, { url: 'https://t.ad/x.js', resourceType: 'script' });
  assert.equal(r.type, DECISION_CANCEL);
  assert.equal(r.reason, 'tracker');
  assert.ok(calls.some((c) => c[0] === 'blockedTracker'));
});

test('PNA 判定拦截时取消，关闭开关则放行', () => {
  const blocked = baseDeps();
  blocked.deps.guards.evaluatePnaRequest = () => ({ block: true, targetSpace: 'loopback' });
  const rb = decideRequest(blocked.deps, { url: 'http://127.0.0.1/', resourceType: 'xhr' });
  assert.equal(rb.type, DECISION_CANCEL);
  assert.equal(rb.reason, 'pna');

  const off = baseDeps();
  off.deps.flags.blockLocalNetworkAccess = false;
  let seenEnabled = null;
  off.deps.guards.evaluatePnaRequest = (_d, opt) => { seenEnabled = opt.enabled; return { block: false }; };
  decideRequest(off.deps, { url: 'http://127.0.0.1/', resourceType: 'xhr' });
  assert.equal(seenEnabled, false);
});

test('混合内容主动块取消、被动内容升级', () => {
  const block = baseDeps();
  block.deps.guards.classifyMixedContent = () => ({ action: 'block', resourceType: 'script' });
  assert.equal(decideRequest(block.deps, { url: 'http://a.test/s.js' }).type, DECISION_CANCEL);

  const upgrade = baseDeps();
  upgrade.deps.guards.classifyMixedContent = () =>
    ({ action: 'upgrade', upgrade: 'https://a.test/i.png' });
  const ru = decideRequest(upgrade.deps, { url: 'http://a.test/i.png' });
  assert.equal(ru.type, DECISION_REDIRECT);
  assert.equal(ru.url, 'https://a.test/i.png');
});

test('mainFrame 剥离追踪参数后重定向一次', () => {
  const { deps } = baseDeps();
  deps.guards.stripTrackingFromUrl = (u) => u.split('?')[0];
  const r = decideRequest(deps, { url: 'https://a.test/?utm_source=x', resourceType: 'mainFrame' });
  assert.equal(r.type, DECISION_REDIRECT);
  assert.equal(r.url, 'https://a.test/');
  assert.equal(r.reason, 'tracking-strip');
});

test('mainFrame 高危钓鱼只发横幅不阻断', () => {
  const { deps, calls } = baseDeps();
  deps.guards.analyzePhish = () => ({
    level: 'high', hostname: 'paypa1.test', url: 'https://paypa1.test/',
    signals: [{ detail: 'userinfo 偷渡' }],
  });
  deps.guards.analyzeBrand = () => ({ hostname: 'paypa1.test' });
  const r = decideRequest(deps, { url: 'https://paypa1.test/', resourceType: 'mainFrame' });
  assert.equal(r.type, DECISION_ALLOW);
  assert.ok(calls.some((c) => c[0] === 'sendToRenderer' && c[1] === 'phish-url-warning'));
  assert.ok(calls.some((c) => c[0] === 'brandSpoof'));
});

test('中低危钓鱼不发高危横幅', () => {
  const { deps, calls } = baseDeps();
  deps.guards.analyzePhish = () => ({ level: 'medium', signals: [] });
  decideRequest(deps, { url: 'https://a.test/', resourceType: 'mainFrame' });
  assert.ok(!calls.some((c) => c[0] === 'sendToRenderer' && c[1] === 'phish-url-warning'));
});

test('HTTPS-only 对公网 http 升级，对私网保留 http', () => {
  const pub = baseDeps();
  pub.deps.flags.httpsOnlyEnabled = true;
  const rp = decideRequest(pub.deps, { url: 'http://a.test/', resourceType: 'mainFrame' });
  assert.equal(rp.type, DECISION_REDIRECT);
  assert.equal(rp.url, 'https://a.test/');

  const priv = baseDeps();
  priv.deps.flags.httpsOnlyEnabled = true;
  priv.deps.guards.isPrivateNetworkHost = () => true;
  const rq = decideRequest(priv.deps, { url: 'http://192.168.1.1/', resourceType: 'mainFrame' });
  assert.equal(rq.type, DECISION_ALLOW);
});

test('HTTPS-only 显式 80 端口收敛到 https 默认 443（不带端口）', () => {
  const d = baseDeps();
  d.deps.flags.httpsOnlyEnabled = true;
  const r = decideRequest(d.deps, { url: 'http://a.test:80/path?x=1', resourceType: 'mainFrame' });
  assert.equal(r.type, DECISION_REDIRECT);
  assert.equal(r.url, 'https://a.test/path?x=1');
});

test('HTTPS-only 非标准端口保留 HTTP 不放行到带同端口的 https', () => {
  const d = baseDeps();
  d.deps.flags.httpsOnlyEnabled = true;
  const r = decideRequest(d.deps, { url: 'http://a.test:8080/app', resourceType: 'mainFrame' });
  assert.equal(r.type, DECISION_ALLOW);
  // 留痕一次，便于安全面板观察“为什么这个站没被升级”。
  assert.ok(d.calls.some((c) => c[0] === 'securityEvent'
    && String(c[3]).indexOf('非标准端口') >= 0));
});

test('HTTPS-only 对用户登记的 HTTP 例外站点不升级', () => {
  const d = baseDeps();
  d.deps.flags.httpsOnlyEnabled = true;
  d.deps.guards.isHttpException = (u) => {
    try { return new URL(u).hostname === 'legacy.test'; } catch { return false; }
  };
  const ex = decideRequest(d.deps, { url: 'http://legacy.test/', resourceType: 'mainFrame' });
  assert.equal(ex.type, DECISION_ALLOW);
  const other = decideRequest(d.deps, { url: 'http://normal.test/', resourceType: 'mainFrame' });
  assert.equal(other.type, DECISION_REDIRECT);
  assert.equal(other.url, 'https://normal.test/');
});

test('HTTPS-only 守卫回调抛异常时退化为不升级、不崩管道', () => {
  const d = baseDeps();
  d.deps.flags.httpsOnlyEnabled = true;
  d.deps.guards.isPrivateNetworkHost = () => { throw new Error('boom'); };
  d.deps.guards.isHttpException = () => { throw new Error('boom'); };
  const r = decideRequest(d.deps, { url: 'http://a.test/', resourceType: 'mainFrame' });
  // 两个查询都抛错时按“既非私网也非例外”处理，公网仍正常升级。
  assert.equal(r.type, DECISION_REDIRECT);
});

test('判定守卫抛异常时不影响后续放行（fail-open 浏览）', () => {
  const { deps } = baseDeps();
  deps.guards.evaluatePnaRequest = () => { throw new Error('boom'); };
  deps.guards.classifyMixedContent = () => { throw new Error('boom'); };
  assert.equal(decideRequest(deps, { url: 'https://a.test/' }).type, DECISION_ALLOW);
});

test('applyPipeline 把三种决策映射成正确的 Electron 回调', () => {
  // 取消：tracker 命中
  {
    const d = baseDeps();
    d.deps.guards.isTrackerRequest = () => true;
    let handler = null;
    const wr = { onBeforeRequest: (fn) => { handler = fn; } };
    const counts = [];
    applyPipeline(wr, d.deps, (_x, b) => counts.push(b));
    let cb = null;
    handler({ url: 'https://t.ad/x.js' }, (x) => { cb = x; });
    assert.deepEqual(cb, { cancel: true });
    assert.deepEqual(counts, [true]);
  }
  // 重定向：https-only，且不计数
  {
    const d = baseDeps();
    d.deps.flags.httpsOnlyEnabled = true;
    let handler = null;
    const wr = { onBeforeRequest: (fn) => { handler = fn; } };
    const counts = [];
    applyPipeline(wr, d.deps, (_x, b) => counts.push(b));
    let cb = null;
    handler({ url: 'http://a.test/', resourceType: 'mainFrame' }, (x) => { cb = x; });
    assert.deepEqual(cb, { redirectURL: 'https://a.test/' });
    assert.deepEqual(counts, []);
  }
  // 放行并计数
  {
    const d = baseDeps();
    let handler = null;
    const wr = { onBeforeRequest: (fn) => { handler = fn; } };
    const counts = [];
    applyPipeline(wr, d.deps, (_x, b) => counts.push(b));
    let cb = null;
    handler({ url: 'https://a.test/', resourceType: 'script' }, (x) => { cb = x; });
    assert.deepEqual(cb, {});
    assert.deepEqual(counts, [false]);
  }
});
