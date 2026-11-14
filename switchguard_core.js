'use strict';

// switchguard.js —— Chromium/Electron 命令行开关与环境变量注入的安全基线。
//
// 威胁模型：
//   Electron 基于 Chromium，进程启动时除了读 process.argv，还会读环境变量
//   ELECTRON_EXTRA_LAUNCH_ARGS（较新版本）把其中内容当作“额外命令行开关”解析。
//   本机恶意软件、被篡改的快捷方式、父进程包装器，或诱骗用户运行的
//       OpenCosy.exe --disable-web-security --remote-debugging-port=9222
//   都能在应用自己的安全代码运行之前就关掉同源策略、挂上远程调试（任意本机进程可经
//   CDP 完全控制浏览器）、把全部流量指到攻击者代理、忽略证书错误。这些开关不经过
//   setPermissionRequestHandler / onHeadersReceived 等任何上层防线。
//
//   因此必须在 app.whenReady 之前解析两类来源（argv 与 ELECTRON_EXTRA_LAUNCH_ARGS），
//   对“一旦出现即破坏安全模型”的开关零容忍：记录后由 main.js 拒绝继续启动；对仅属
//   降硬的 warn 开关记录但放行。纯解析/判定在本模块，实际退出动作在 main.js。

const {
  SEVERITY_CRITICAL,
  analyzeFlag,
  splitExtraLaunchArgs,
  tokenizeSwitchArgs
} = require('./switchguard_decide_core');

// auditSwitches 审计 argv 与环境变量两类来源。
// input: { argv:string[], extraLaunchArgs:string }
// 返回 { findings:[{flag,severity,code,reason}], hasCritical, criticalFlags, warnFlags }。
function auditSwitches(input) {
  const inp = input || {};
  const argvFlags = tokenizeSwitchArgs(inp.argv, 'argv');
  const extraFlags = tokenizeSwitchArgs(
    splitExtraLaunchArgs(inp.extraLaunchArgs), 'env:ELECTRON_EXTRA_LAUNCH_ARGS');
  const all = argvFlags.concat(extraFlags);

  const findings = [];
  const criticalFlags = [];
  const warnFlags = [];
  for (const flag of all) {
    const verdict = analyzeFlag(flag);
    if (!verdict) continue;
    findings.push({ flag, severity: verdict.severity, code: verdict.code, reason: verdict.reason });
    if (verdict.severity === SEVERITY_CRITICAL) criticalFlags.push(flag);
    else warnFlags.push(flag);
  }
  return {
    findings,
    hasCritical: criticalFlags.length > 0,
    criticalFlags,
    warnFlags,
    envInjected: extraFlags.length > 0,
  };
}

// collectSources 从类 process 对象抽出两类来源，便于测试注入。
function collectSources(proc) {
  const p = proc || {};
  const env = p.env || {};
  return {
    argv: Array.isArray(p.argv) ? p.argv.slice(2) : [], // 去掉可执行文件与应用路径
    extraLaunchArgs: env.ELECTRON_EXTRA_LAUNCH_ARGS || '',
  };
}

module.exports = {
  SEVERITY_CRITICAL,
  auditSwitches,
  collectSources,
};
