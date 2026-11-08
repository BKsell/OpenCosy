'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const g = require('./netauthguard');

// ---------- parseHttpUrl / authHostKey ----------

test('parseHttpUrl 只接受 http/https', () => {
  assert.ok(g.parseHttpUrl('http://example.com/'));
  assert.ok(g.parseHttpUrl('https://example.com:8443/a?b=1'));
  for (const bad of ['file:///etc/passwd', 'ftp://x/y', 'javascript:alert(1)', '', null, undefined, 42, 'http://']) {
    assert.equal(g.parseHttpUrl(bad), null, `应拒绝 ${String(bad)}`);
  }
});

test('authHostKey 归一化主机并保留显式端口、忽略路径', () => {
  assert.equal(
    g.authHostKey('https://Example.COM:8443/deep/path?x=1'),
    'https://example.com:8443'
  );
  assert.equal(g.authHostKey('http://intranet/'), 'http://intranet');
  // 同主机不同端口是不同主体，不能共享限流额度
  assert.notEqual(
    g.authHostKey('http://h:8080/'),
    g.authHostKey('http://h:9090/')
  );
  assert.equal(g.authHostKey('not a url'), '');
});

// ---------- classifyServerAuth ----------

test('主框架 http/https 已知方案 => prompt', () => {
  for (const scheme of ['basic', 'digest', 'ntlm', 'negotiate', 'BASIC', ' NTLM ']) {
    const r = g.classifyServerAuth({
      url: 'http://intranet/login',
      isMainFrame: true,
      authInfo: { scheme, realm: 'CORP' },
    });
    assert.equal(r.decision, 'prompt', `${scheme} 应弹框`);
    assert.equal(r.key, 'http://intranet');
  }
});

test('子框架 401 一律静默取消（凭据探测防线）', () => {
  const r = g.classifyServerAuth({
    url: 'http://intranet/secret',
    isMainFrame: false,
    authInfo: { scheme: 'ntlm', realm: 'X' },
  });
  assert.equal(r.decision, 'cancel');
  assert.equal(r.reason, 'subframe-credential-probe');
});

test('未显式传 isMainFrame 时按子框架处理（fail-closed）', () => {
  const r = g.classifyServerAuth({ url: 'http://x/', authInfo: { scheme: 'basic' } });
  assert.equal(r.decision, 'cancel');
  assert.equal(r.reason, 'subframe-credential-probe');
});

test('非 http(s) URL 与未知认证方案 => cancel', () => {
  const a = g.classifyServerAuth({ url: 'file:///c:/x', isMainFrame: true, authInfo: { scheme: 'basic' } });
  assert.equal(a.decision, 'cancel');
  assert.equal(a.reason, 'non-http-url');

  const b = g.classifyServerAuth({ url: 'http://x/', isMainFrame: true, authInfo: { scheme: 'weirdface' } });
  assert.equal(b.decision, 'cancel');
  assert.equal(b.reason, 'unknown-auth-scheme');
});

test('realm 控制字符被清理且限长', () => {
  const long = 'A'.repeat(g.MAX_REALM_CHARS + 50);
  const r = g.classifyServerAuth({
    url: 'http://x/',
    isMainFrame: true,
    authInfo: { scheme: 'basic', realm: 'a\x00b\x07\n' + long },
  });
  assert.equal(r.decision, 'prompt');
  assert.match(r.realm, /^a b/);
  assert.equal(r.realm.length, g.MAX_REALM_CHARS);
});

// ---------- classifyProxyAuth ----------

test('代理 407 已知方案 => prompt，键带 proxy: 前缀', () => {
  const r = g.classifyProxyAuth({
    url: 'http://target/',
    authInfo: { scheme: 'basic', host: 'proxy.corp', port: 3128 },
  });
  assert.equal(r.decision, 'prompt');
  assert.equal(r.reason, 'proxy-407');
  assert.equal(r.key, 'proxy:proxy.corp:3128');
});

test('代理键在缺 host 时回退、未知方案取消', () => {
  const a = g.classifyProxyAuth({ url: 'http://target/', authInfo: { scheme: 'digest' } });
  assert.equal(a.decision, 'prompt');
  assert.equal(a.key, 'proxy:session');

  const b = g.classifyProxyAuth({ authInfo: { scheme: 'ntlm', host: 'p', port: 0 } });
  assert.equal(b.decision, 'prompt');
  assert.equal(b.key, 'proxy:p');

  const c = g.classifyProxyAuth({ url: 'http://t/', authInfo: { scheme: 'mystery' } });
  assert.equal(c.decision, 'cancel');
  assert.equal(c.reason, 'unknown-auth-scheme');
});

// ---------- AuthPromptRateLimiter ----------

test('限流器：窗口内达到上限后拒绝并进入冷却', () => {
  const rl = new g.AuthPromptRateLimiter({ max: 3, windowMs: 1000, cooldownMs: 5000 });
  const t0 = 10_000;
  assert.deepEqual(rl.request('h', t0).allow, true);
  assert.deepEqual(rl.request('h', t0 + 100).allow, true);
  assert.deepEqual(rl.request('h', t0 + 200).allow, true);
  const blocked = rl.request('h', t0 + 300);
  assert.equal(blocked.allow, false);
  assert.equal(blocked.reason, 'rate-limited');
  // 已进入冷却，即便时间仍在原窗口内也直接 cooldown
  assert.equal(rl.request('h', t0 + 400).reason, 'cooldown');
  // 冷却结束后恢复
  assert.equal(rl.request('h', t0 + 6000).allow, true);
});

test('滑窗过期后额度自动恢复（不进入冷却）', () => {
  const rl = new g.AuthPromptRateLimiter({ max: 2, windowMs: 1000, cooldownMs: 9999 });
  assert.equal(rl.request('h', 0).allow, true);
  assert.equal(rl.request('h', 100).allow, true);
  // 1200ms 后最早两次都滑出窗口
  assert.equal(rl.request('h', 1200).allow, true);
});

test('限流按 key 独立，坏 key 拒绝', () => {
  const rl = new g.AuthPromptRateLimiter({ max: 1, windowMs: 1000, cooldownMs: 1000 });
  assert.equal(rl.request('a', 0).allow, true);
  assert.equal(rl.request('b', 0).allow, true);
  assert.equal(rl.request('a', 10).allow, false);
  assert.equal(rl.request('', 0).allow, false);
});

test('reset 清掉轰炸历史与冷却', () => {
  const rl = new g.AuthPromptRateLimiter({ max: 1, windowMs: 1000, cooldownMs: 10000 });
  assert.equal(rl.request('h', 0).allow, true);
  assert.equal(rl.request('h', 1).allow, false);
  rl.reset('h');
  assert.equal(rl.request('h', 2).allow, true);
});

// ---------- chooseClientCertificate ----------

test('无记住选择时绝不自动发送客户端证书', () => {
  const list = [{ fingerprint: 'SHA256:AA:BB' }, { fingerprint: 'SHA256:CC:DD' }];
  const r = g.chooseClientCertificate({ certificateList: list });
  assert.equal(r.index, -1);
  assert.equal(r.reason, 'no-remembered-choice');
  assert.equal(g.chooseClientCertificate({ certificateList: [] }).reason, 'no-certificate');
});

test('记住的指纹精确命中才选择，大小写/冒号归一', () => {
  const list = [
    { fingerprint: 'SHA256:aa:bb:cc' },
    { fingerprint: 'SHA256:de:ad:be' },
  ];
  const ok = g.chooseClientCertificate({ certificateList: list, rememberedFingerprint: 'sha256:DE:AD:BE' });
  assert.equal(ok.index, 1);
  assert.equal(ok.reason, 'remembered');

  const gone = g.chooseClientCertificate({ certificateList: list, rememberedFingerprint: 'SHA256:00:11' });
  assert.equal(gone.index, -1);
  assert.equal(gone.reason, 'remembered-cert-absent');
});

test('normalizeCertFingerprint 支持 sha1/sha256 前缀并剔除杂字符', () => {
  assert.equal(g.normalizeCertFingerprint('SHA1:AB:CD'), 'abcd');
  assert.equal(g.normalizeCertFingerprint('sha256:AA-BB'), 'aabb');
  assert.equal(g.normalizeCertFingerprint(null), '');
});

// ---------- sanitizeAuthSubmit ----------

test('合法账号口令通过；空口令允许', () => {
  const r = g.sanitizeAuthSubmit({ username: ' alice ', password: 'p@ss' });
  assert.equal(r.ok, true);
  assert.equal(r.username, 'alice');
  const emptyPw = g.sanitizeAuthSubmit({ username: 'bob', password: '' });
  assert.equal(emptyPw.ok, true);
  assert.equal(emptyPw.password, '');
});

test('账号口令净化：去控制字符、拒空账号、拒超长、拒错类型', () => {
  const ctrl = g.sanitizeAuthSubmit({ username: 'a\x00b', password: 'x' });
  assert.equal(ctrl.ok, true);
  assert.equal(ctrl.username, 'ab');

  assert.equal(g.sanitizeAuthSubmit({ username: '', password: 'x' }).ok, false);
  assert.equal(g.sanitizeAuthSubmit({ username: 'x', password: 123 }).ok, false);
  assert.equal(g.sanitizeAuthSubmit(null).ok, false);
  const longUser = g.sanitizeAuthSubmit({ username: 'u'.repeat(g.MAX_USERNAME_CHARS + 1), password: 'x' });
  assert.equal(longUser.ok, false);
  const longPw = g.sanitizeAuthSubmit({ username: 'u', password: 'p'.repeat(g.MAX_PASSWORD_CHARS + 1) });
  assert.equal(longPw.ok, false);
});

// ---------- describeAuthScheme ----------

test('describeAuthScheme 仅对已知方案返回名称', () => {
  assert.ok(g.describeAuthScheme('basic').includes('Basic'));
  assert.ok(g.describeAuthScheme(' NTLM ').includes('NTLM'));
  assert.equal(g.describeAuthScheme('bogus'), '');
});

// ---------- 常量自洽 ----------

test('安全常量取值合理', () => {
  assert.ok(g.DEFAULT_MAX_PROMPTS_IN_WINDOW >= 1 && g.DEFAULT_MAX_PROMPTS_IN_WINDOW <= 10);
  assert.ok(g.AUTH_PROMPT_TIMEOUT_MS >= 30_000);
  assert.ok(g.MAX_PENDING_PROMPTS > 0 && g.MAX_PENDING_PROMPTS <= 128);
  assert.ok(g.KNOWN_AUTH_SCHEMES.has('ntlm'));
});

// ---------- RememberedClientCertStore ----------

test('cert store remember/get/forget/clear roundtrip', () => {
  const store = new g.RememberedClientCertStore();
  const cert = {
    fingerprint: 'SHA256:ab:cd',
    issuerName: 'Corp CA',
    subjectName: 'CN=client',
    serialNumber: '01',
  };
  assert.equal(store.remember('portal.corp', cert, 100), true);
  const got = store.get('portal.corp');
  assert.ok(got);
  assert.equal(got.host, 'https://portal.corp');
  assert.equal(got.fingerprint, 'abcd');
  assert.equal(store.list().length, 1);
  assert.equal(store.forget('portal.corp'), true);
  assert.equal(store.get('portal.corp'), null);
  store.remember('a', cert);
  store.clear();
  assert.equal(store.list().length, 0);
});

test('cert store rejects missing fingerprint/host', () => {
  const store = new g.RememberedClientCertStore();
  assert.equal(store.remember('ok.com', { fingerprint: '' }), false);
  assert.equal(store.remember('', { fingerprint: 'SHA1:AA' }), false);
  assert.equal(store.list().length, 0);
});

test('cert store evicts least recently used and refreshes existing', () => {
  const store = new g.RememberedClientCertStore({ max: 2 });
  store.remember('h1', { fingerprint: 'SHA1:01' }, 10);
  store.remember('h2', { fingerprint: 'SHA1:02' }, 20);
  store.remember('h1', { fingerprint: 'SHA1:01' }, 30);
  store.remember('h3', { fingerprint: 'SHA1:03' }, 40);
  const hosts = store.list().map(r => r.host).sort();
  assert.deepEqual(hosts, ['https://h1', 'https://h3']);
  assert.equal(store.list().length, 2);
});

test('cert store toJSON/loadJSON sanitizes and skips bad rows', () => {
  const store = new g.RememberedClientCertStore();
  store.remember('a.com', { fingerprint: 'SHA256:aa:bb', issuerName: 'CA' }, 5);
  const json = JSON.stringify(store.toJSON());

  const store2 = new g.RememberedClientCertStore();
  const polluted = JSON.stringify({
    version: 1,
    choices: [
      ...JSON.parse(json).choices,
      { host: '', fingerprint: 'xx' },
      { host: 'b.com', fingerprint: '' },
      null,
    ],
  });
  const loaded = store2.loadJSON(polluted);
  assert.equal(loaded, 1);
  assert.equal(store2.list().length, 1);
  assert.equal(store2.list()[0].host, 'https://a.com');
  assert.equal(store2.loadJSON('{not json'), 0);
});

test('sanitizeCertChoiceRecord limits fields and coerces types', () => {
  const r = g.sanitizeCertChoiceRecord({
    host: 'h.com',
    fingerprint: 'SHA256:AB',
    issuer: 'x'.repeat(9999),
    subject: 123,
    updatedAt: 'notnum',
  });
  assert.ok(r);
  assert.equal(r.issuer.length, g.MAX_ISSUER_CHARS);
  assert.equal(r.subject, '');
  assert.equal(r.updatedAt, 0);
  assert.equal(g.sanitizeCertChoiceRecord({ host: 'h' }), null);
});

// ---------- AuthPromptStats ----------

test('stats count decisions and aggregate dimensions', () => {
  const s = new g.AuthPromptStats();
  s.recordEvent({ decision: 'prompt', reason: 'main-frame-401', scheme: 'basic' });
  s.recordEvent({ decision: 'cancel', reason: 'subframe-credential-probe', scheme: 'ntlm' });
  s.recordEvent({ decision: 'cancel', reason: 'subframe-credential-probe', scheme: 'ntlm' });
  s.recordRateLimited();
  s.recordSuccess();
  s.recordCertSuppressed();
  const j = s.toJSON();
  assert.equal(j.total, 3);
  assert.equal(j.prompted, 1);
  assert.equal(j.cancelled, 2);
  assert.equal(j.rateLimited, 1);
  assert.equal(j.succeeded, 1);
  assert.equal(j.certSuppressed, 1);
  assert.equal(j.byReason['subframe-credential-probe'], 2);
  assert.equal(j.byScheme.ntlm, 2);
});

test('stats dimension maps stop growing past cap', () => {
  const s = new g.AuthPromptStats();
  for (let i = 0; i < g.MAX_STATS_KEYS + 10; i++) {
    s.recordEvent({ decision: 'cancel', reason: 'r' + i, scheme: 'basic' });
  }
  assert.ok(Object.keys(s.toJSON().byReason).length <= g.MAX_STATS_KEYS);
});
