'use strict';

// wsoriginguard.js —— WebSocket 连接源校验。
//
// 页面里 new WebSocket('wss://internal.host/') 是一个常见 exfil/SSRF 通道：
//
//   - https 页面连 ws:// 明文（混合内容泄露）；
//   - 公网页面连 127.0.0.1 / 内网域名（打本地服务）；
//   - 跨源 ws 没像 fetch 那样被 CORS 拦。
//
// 这里把“这个 WebSocket URL 该不该让它连出去”收敛成纯函数。

const PRIVATE_HOSTS = new Set([
	'localhost', '127.0.0.1', '::1',
	'0.0.0.0', 'metadata.google.internal',
]);

// decideWebSocket 入参：
//   pageOrigin   当前页 origin（protocol//host:port）
//   wsUrl        要连接的 ws(s):// URL
//   allowPrivate 布尔，是否允许连内网（默认 false）
// 返回 { action:'allow'|'block', reason }
function decideWebSocket(pageOrigin, wsUrl, allowPrivate) {
	let u;
	try {
		u = new URL(wsUrl);
	} catch (_) {
		return { action: 'block', reason: 'bad-url' };
	}
	if (u.protocol !== 'ws:' && u.protocol !== 'wss:') {
		return { action: 'block', reason: 'bad-scheme' };
	}
	let origin;
	try {
		origin = new URL(pageOrigin);
	} catch (_) {
		return { action: 'block', reason: 'bad-page-origin' };
	}
	// https 页必须 wss。
	if (origin.protocol === 'https:' && u.protocol !== 'wss:') {
		return { action: 'block', reason: 'mixed-content-ws' };
	}
	const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
	if (!allowPrivate && PRIVATE_HOSTS.has(host)) {
		return { action: 'block', reason: 'private-host' };
	}
	if (host.endsWith('.internal') || host.endsWith('.local')) {
		return { action: 'block', reason: 'local-suffix' };
	}
	return { action: 'allow', reason: 'ok' };
}

// shouldShowWsWarning 是否给用户弹“正在连第三方 WebSocket”提示（跨源时）。
function shouldShowWsWarning(pageOrigin, wsUrl) {
	try {
		const a = new URL(pageOrigin);
		const b = new URL(wsUrl);
		return a.hostname !== b.hostname;
	} catch (_) {
		return false;
	}
}

module.exports = {
	PRIVATE_HOSTS,
	decideWebSocket,
	shouldShowWsWarning,
};
