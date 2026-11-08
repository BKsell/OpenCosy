'use strict';

// credentialbreachcheck.js —— 本地弱口令/疑似撞库口令预检（纯函数，不联网）。
//
// 真实的 HaveIBeenPwned 是 k-anonymity 远程查询；本模块只做离线第一道闸：
// 挡掉常见弱口令、过短口令、纯重复/纯序列口令，避免用户把这类口令存进密码库
// 或自动填进登录框。它不替代远程泄露库查询，也不存储用户口令。

const COMMON_WEAK = new Set([
	'password', '123456', '123456789', '12345678', '12345', '111111',
	'qwerty', 'abc123', 'password1', 'iloveyou', 'dragon', 'monkey',
	'letmein', 'admin', 'welcome', 'sunshine', 'princess', 'football',
]);

// evaluatePassword 返回 { ok, score(0-4), reasons[] }。
function evaluatePassword(pwd) {
	const reasons = [];
	const s = String(pwd == null ? '' : pwd);
	if (s.length < 8) reasons.push('too-short');
	if (s.length > 128) reasons.push('too-long');

	const lower = s.toLowerCase();
	if (COMMON_WEAK.has(lower)) reasons.push('common-weak');

	let classes = 0;
	if (/[a-z]/.test(s)) classes += 1;
	if (/[A-Z]/.test(s)) classes += 1;
	if (/[0-9]/.test(s)) classes += 1;
	if (/[^A-Za-z0-9]/.test(s)) classes += 1;
	if (classes < 3) reasons.push('weak-classes');

	// 纯重复字符（aaaa）或纯顺序（abcdef / 123456）。
	if (/^(.)\1+$/.test(s)) reasons.push('repeated-char');
	if (isSequence(s)) reasons.push('sequential');

	const ok = reasons.length === 0;
	const score = Math.max(0, Math.min(4, classes + (s.length >= 12 ? 1 : 0)));
	return { ok, score, reasons };
}

// isSequence 粗略判定 a-b-c / 1-2-3 这类连续串（长度>=4 即判弱）。
function isSequence(s) {
	if (s.length < 4) return false;
	const lower = s.toLowerCase();
	let run = 1;
	for (let i = 1; i < lower.length; i += 1) {
		const d = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
		if (d === 1 || d === -1) {
			run += 1;
			if (run >= 4) return true;
		} else {
			run = 1;
		}
	}
	return false;
}

// shouldWarnBeforeSave 是给保存口令前弹窗用的便捷入口。
function shouldWarnBeforeSave(pwd) {
	return !evaluatePassword(pwd).ok;
}

module.exports = {
	COMMON_WEAK,
	evaluatePassword,
	isSequence,
	shouldWarnBeforeSave,
};
