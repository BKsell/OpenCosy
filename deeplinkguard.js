'use strict';

const { isSwitchLike, reviewStartupArg } = require('./deeplinkguard_schemes');

// MAX_ARGV_SCAN 限制我们愿意扫描的命令行参数数量，防止异常超长 argv 拖垮启动。
const MAX_ARGV_SCAN = 64;

// pickDeepLinkFromArgv 从 process.argv 形态的数组里找出第一个合法深链。
// Windows 下协议处理器拉起浏览器时，深链在参数中的位置并不固定（可能伴随
// Chromium 自己的开关、可能不在 argv[1]），因此不能写死取 argv[1]。
// 规则：跳过 '-' 开头的开关及其可能的取值（保守起见只跳过开关本身）、跳过
// 可执行文件路径本身（argv[0]），逐条交给 reviewStartupArg，返回首个通过者。
function pickDeepLinkFromArgv(argv, allowedHosts) {
  if (!Array.isArray(argv)) return null;
  const end = Math.min(argv.length, MAX_ARGV_SCAN + 1);
  for (let i = 1; i < end; i++) {
    const raw = argv[i];
    if (typeof raw !== 'string' || raw === '') continue;
    if (isSwitchLike(raw.trim())) continue;
    const review = reviewStartupArg(raw, allowedHosts);
    if (review.ok) return review;
    // 非开关但不合法的参数：继续找下一个（例如 argv 里混着无意义的路径片段），
    // 不在这里记审计，由调用方决定是否需要。
  }
  return null;
}

// describeReason 稳定中文说明（不回显完整输入）。
function describeReason(reason) {
  const map = {
    'not-string': '深链不是字符串',
    empty: '深链为空',
    'too-long': '深链过长',
    'control-char': '深链含控制字符',
    'switch-like': '深链形似命令行开关',
    unparseable: '深链无法解析',
    scheme: '不允许的深链协议',
    'no-host': '深链缺少主机名',
    host: '内部深链主机不在白名单',
    unc: '不接受网络共享(UNC)路径',
    'not-absolute': '本地文件必须是绝对路径',
    'not-html': '只接受 .html/.htm 文件',
    traversal: '本地路径含目录穿越',
  };
  return Object.prototype.hasOwnProperty.call(map, reason) ? map[reason] : '不安全的深链';
}
