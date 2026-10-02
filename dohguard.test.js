'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('./dohguard');

test('模式归一：非法值回退 automatic', () => {
  assert.equal(d.normalizeMode('secure'), 'secure');
  assert.equal(d.normalizeMode('off'), 'off');
  assert.equal(d.normalizeMode('bogus'), 'automatic');
  assert.equal(d.normalizeMode(undefined), 'automatic');
});

test('IPv4 解析：拒绝前导零与越界段', () => {
  assert.equal(d.parseIPv4('1.2.3.4'), (1 << 24) >>> 0 | (2 << 16) | (3 << 8) | 4);
  assert.equal(d.parseIPv4('010.0.0.1'), null);
  assert.equal(d.parseIPv4('256.1.1.1'), null);
  assert.equal(d.parseIPv4('1.2.3'), null);
});

test('IPv4 私网 / 回环 / 链路本地 / CGNAT 判定', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.9', '172.31.255.255',
    '192.168.4.5', '169.254.169.254', '100.64.0.1', '0.0.0.0']) {
    assert.equal(d.ipv4IsPrivate(d.parseIPv4(ip)), true, `${ip} 应判私网`);
  }
  for (const ip of ['172.15.0.1', '172.32.0.1', '100.63.0.1', '8.8.8.8', '1.1.1.1', '172.20.0.1']) {
    if (ip === '172.20.0.1') continue; // 172.20 属 172.16/12 私网
    assert.equal(d.ipv4IsPrivate(d.parseIPv4(ip)), false, `${ip} 应判公网`);
  }
  assert.equal(d.ipv4IsPrivate(d.parseIPv4('172.20.0.1')), true);
});

test('hostIsPrivateLiteral：本机名 / 内网 IP / IPv6 环回', () => {
  for (const h of ['localhost', 'foo.localhost', 'host.local', 'host.internal',
    '127.0.0.1', '10.0.0.2', '192.168.1.1', '169.254.169.254',
    '::1', '[::1]', 'fe80::1', 'fc00::1', 'fd12::1', '::ffff:127.0.0.1',
    '::ffff:192.168.0.1']) {
    assert.equal(d.hostIsPrivateLiteral(h), true, `${h} 应判私有/本机`);
  }
});

test('hostIsPrivateLiteral：公网域名与公网 IP 放行，非法字面量拒绝', () => {
  for (const h of ['cloudflare-dns.com', 'dns.google', '8.8.8.8', '1.1.1.1',
    '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(d.hostIsPrivateLiteral(h), false, `${h} 应判公网`);
  }
  // 怪异 / 非法字面量保守拒绝
  assert.equal(d.hostIsPrivateLiteral('999.1.1.1'), true);
  assert.equal(d.hostIsPrivateLiteral('gg:::1'), true);
});

test('validateDohServer：合法白名单模板通过', () => {
  for (const p of d.KNOWN_PROVIDERS) {
    const r = d.validateDohServer(p.template);
    assert.equal(r.ok, true, `${p.id} 模板应合法`);
    assert.equal(r.template, p.template);
  }
});

test('validateDohServer：拒绝非 https / 凭据 / 内网 / 碎片 / 空路径', () => {
  const bad = [
    'http://dns.example.com/dns-query',   // 非 https
    'https://user:pwd@dns.example.com/x', // 凭据
    'https://127.0.0.1/dns-query',        // 回环
    'https://192.168.1.1/dns-query',      // 内网
    'https://169.254.169.254/dns-query',  // 元数据
    'https://dns.example.com/dns-query#frag', // 碎片
    'https://dns.example.com',            // 无路径
    'ftp://dns.example.com/x',
    '',
  ];
  for (const u of bad) {
    const r = d.validateDohServer(u);
    assert.equal(r.ok, false, `${u} 应被拒绝`);
    assert.ok(r.reason);
  }
});

test('validateDohServer：端口约束', () => {
  assert.equal(d.validateDohServer('https://dns.example.com:8443/dns-query').ok, true);
  assert.equal(d.validateDohServer('https://dns.example.com:53/dns-query').ok, false);
  assert.equal(d.validateDohServer('https://dns.example.com:443/dns-query').ok, true);
});

test('resolveServer：白名单 id 与 custom', () => {
  const a = d.resolveServer('cloudflare');
  assert.equal(a.ok, true);
  assert.equal(a.source, 'cloudflare');
  assert.ok(a.template.includes('cloudflare-dns.com'));

  assert.equal(d.resolveServer('nope').ok, false);

  const c = d.resolveServer('custom', 'https://doh.example.org/dns-query');
  assert.equal(c.ok, true);
  assert.equal(c.source, 'custom');

  const bad = d.resolveServer('custom', 'http://10.0.0.1/x');
  assert.equal(bad.ok, false);
});

test('resolveControls：off 不指定服务器', () => {
  const r = d.resolveControls({ mode: 'off' });
  assert.equal(r.mode, 'off');
  assert.deepEqual(r.controls, { secureDnsMode: 'off' });
});

test('resolveControls：secure 携带服务器，非法自定义回退 automatic 并告警', () => {
  const ok = d.resolveControls({ mode: 'secure', provider: 'google' });
  assert.equal(ok.controls.secureDnsMode, 'secure');
  assert.ok(Array.isArray(ok.controls.secureDnsServers));
  assert.equal(ok.controls.secureDnsServers.length, 1);

  const fallback = d.resolveControls({ mode: 'secure', provider: 'custom', customUrl: 'http://127.0.0.1' });
  assert.equal(fallback.mode, 'automatic');
  assert.equal(fallback.controls.secureDnsMode, 'automatic');
  assert.ok(fallback.warning);
});

test('台账有界并可序列化往返', () => {
  const led = d.createDohLedger(2);
  led.add({ mode: 'secure', event: 'applied', detail: 'google' });
  led.add({ mode: 'automatic', event: 'fallback', detail: 'not-https' });
  led.add({ mode: 'off', event: 'changed' });
  assert.ok(led.size() <= 2);
  const json = led.toJSON();
  const led2 = d.createDohLedger(5);
  led2.load(json);
  assert.ok(led2.size() >= 1);
  led2.clear();
  assert.equal(led2.size(), 0);
});
