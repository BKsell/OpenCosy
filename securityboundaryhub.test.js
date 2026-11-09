'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const hub = require('./securityboundaryhub');

test('安全响应头链路无告警', () => {
  const r = hub.inspectResponseHeaders({ 'content-type': 'text/html; charset=utf-8', 'content-encoding': 'gzip', 'content-length': '1024', 'set-cookie': 'sid=1; Path=/; Secure' }, 'example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.findings.length, 3);
});

test('跨域 Cookie 在响应头链路中被标记', () => {
  const r = hub.inspectResponseHeaders({ 'set-cookie': ['sid=1; Domain=evil.example', 'ok=1', 'Path=/; HttpOnly'] }, 'example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.findings[0].area, hub.AREA.COOKIE);
});

test('异常压缩响应被标记', () => {
  const r = hub.inspectResponseHeaders({ 'content-encoding': 'gzip, br, deflate' }, 'example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.findings[0].reason, 'multiple-encodings');
});

test('非法 Content-Type 被标记', () => {
  const r = hub.inspectResponseHeaders({ 'content-type': 'text/html; charset=gbk' }, 'example.com');
  assert.strictEqual(r.changed, true);
  const mimeFindings = r.findings.filter((item) => item.area === hub.AREA.MIME);
  assert.strictEqual(mimeFindings.length, 1);
  assert.strictEqual(mimeFindings[0].changed, true);
});

test('含原型污染键的 IPC 负载被标记', () => {
  const payload = JSON.parse('{"__proto__":{"admin":true}}');
  const r = hub.inspectIpcRequest([payload]);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.findings[0].area, hub.AREA.IPC_PAYLOAD);
});

test('正常 IPC 负载放行', () => {
  const r = hub.inspectIpcRequest([{ tabId: 1, url: 'https://example.com' }]);
  assert.strictEqual(r.changed, false);
});

test('IPC 返回值超限被标记', () => {
  const big = { text: 'x'.repeat(40000) };
  const r = hub.inspectIpcReply(big);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.IPC_REPLY);
});

test('路径穿越被标记', () => {
  const r = hub.inspectPathWithin('/home/user/data', '../../etc/passwd');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.PATH);
});

test('超大 JSON 导入被标记', () => {
  const r = hub.inspectImportJson('{"a":' + '1'.repeat(3000000) + '}');
  assert.strictEqual(r.changed, true);
});

test('危险扩展名下载被标记', () => {
  const r = hub.inspectDownloadCandidate({ name: 'invoice.pdf.exe', url: 'https://example.com/x', mime: 'application/pdf', size: 1024 });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.DOWNLOAD);
});

test('伪装图片的可执行文件被标记', () => {
  const r = hub.inspectDownloadedBuffer(Buffer.from('MZ' + 'a'.repeat(300)), 'image/png');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.FILE_MAGIC);
});

test('剪贴板控制字符被清洗', () => {
  const r = hub.sanitizeClipboard('a\u0007b');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.CLIPBOARD);
});

test('日志凭据被脱敏', () => {
  const r = hub.redactText('Authorization: Bearer abcdefgh12345678');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.SECRET);
});

test('跨源重定向剥离凭据', () => {
  const r = hub.inspectRedirectHop({ from: 'https://a.example.com/', to: 'https://b.example.com/', headers: { Authorization: 'Bearer x', Accept: 'text/html' } });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.REDIRECT);
});

test('不安全代理配置被标记', () => {
  const r = hub.inspectProxySettings({ mode: 'pac_script', pacScript: { url: 'http://example.com/p.pac' } });
  assert.strictEqual(r.changed, true);
});

test('SRI 不匹配被标记', () => {
  const body = Buffer.from('payload');
  const r = hub.inspectIntegrity(body, 'sha256-' + crypto.createHash('sha256').update('other').digest('base64'));
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.SRI);
});

test('非法更新清单被标记', () => {
  const r = hub.inspectUpdateManifest({ version: '1.0', url: 'http://x/y', sha512: 'a'.repeat(128), size: 10, signature: '', platform: 'linux-x64' });
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.UPDATE);
});

test('CSP 缺少 nonce 被标记', () => {
  const nonce = crypto.randomBytes(16).toString('base64');
  const r = hub.inspectCspPolicy("script-src 'self'", nonce);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.CSP);
});

test('危险压缩包条目被标记', () => {
  const r = hub.inspectArchiveEntries(['../../evil.sh']);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.ARCHIVE);
});

test('CSV 公式注入被转义', () => {
  const r = hub.sanitizeCsvRows([['=cmd|calc']]);
  assert.strictEqual(r.changed, true);
});

test('SVG 脚本被标记', () => {
  const r = hub.inspectSvgDocument('<svg><script>alert(1)</script></svg>');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.SVG);
});

test('PDF 主动内容被标记', () => {
  const r = hub.inspectPdfDocument(Buffer.from('%PDF-1.7\n<< /OpenAction 1 0 R >>'));
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.PDF);
});

test('HTML 注入文本被标记', () => {
  const r = hub.inspectHtmlText('<img src=x onerror=alert(1)>');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.area, hub.AREA.HTML_TEXT);
});

test('链路覆盖全部安全域', () => {
  assert.strictEqual(hub.CHAIN_AREAS.length, 21);
});

test('告警描述可读', () => {
  const text = hub.describeFindings([{ area: hub.AREA.COOKIE, reason: 'domain-mismatch', changed: true }]);
  assert.ok(text.includes('Cookie'));
});
