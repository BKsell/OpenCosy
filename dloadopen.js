'use strict';

// dloadopen.js —— “点开一个已下载文件”这一步的纯决策内核（不依赖 Electron / fs）。
//
// 背景：下载完成的文件有两个入口会触发系统打开——下载列表里的“打开文件”，
// 以及系统通知的点击回调。后者此前直接 shell.openPath(savePath)，既不过
// 路径消毒（shellGuard.reviewLocalLaunchPath），也不过“来自互联网的可执行/
// 容器二次确认”，等于给 drive-by 下载留了一条从通知栏直通执行的旁路。
//
// 本内核只回答“这一步该不该打开、要不要先确认、还是只定位不执行”，把 UI 与
// 系统调用留给调用方（main 进程）。判定输入全部来自文件名与来源信息，便于单测。

const dloadGuard = require('./dloadguard');
const containerGuard = require('./container');
const quarantine = require('./quarantine');

const ACTION = Object.freeze({
  OPEN: 'open',       // 直接交给系统打开
  CONFIRM: 'confirm', // 先弹确认（可执行 / 伪装 / 来自互联网的容器）
  REVEAL: 'reveal',   // 不执行，只在资源管理器里定位
  BLOCK: 'block',     // 直接拒绝（文件名非法或路径为空）
});

// 本地网页/矢量文件以 file:// 来源打开即可执行内嵌脚本，脱离站点沙箱与 CSP，
// 这类文件一律只定位不执行——需要看内容时用户在浏览器里显式打开。
const LOCAL_WEB_EXTS = new Set(['html', 'htm', 'xhtml', 'svg', 'mhtml', 'mht']);

// 容器里只有“挂载/解包后立刻可执行”的类型才值得打断用户；普通压缩包定位即可。
const MOUNTABLE_EXTS = new Set(['iso', 'img', 'vhd', 'vhdx', 'vmdk']);

function extOfName(name) {
  const base = String(name || '');
  const i = base.lastIndexOf('.');
  if (i <= 0 || i === base.length - 1) return '';
  return base.slice(i + 1).toLowerCase();
}

function verdict(action, reason, extra) {
  return Object.assign({ action, reason, reasons: extra && extra.reasons ? extra.reasons : [] }, extra || {});
}

// decideOpenTarget 输入：
//   filePath  已解析的绝对路径（调用方负责 path.resolve）
//   filename  落盘文件名（通常 path.basename(filePath)）
//   hostUrl   下载来源 URL；未知传 null
//   mime      响应 MIME（可选，用于 MIME/扩展名矛盾判定）
// 返回 { action, reason, reasons, analysis? }。
function decideOpenTarget(input) {
  const filePath = String((input && input.filePath) || '');
  const filename = String((input && input.filename) || '');
  const hostUrl = (input && input.hostUrl) || null;
  const mime = input && input.mime;

  if (filePath.trim() === '' || filename.trim() === '') {
    return verdict(ACTION.BLOCK, 'empty-target');
  }

  const analysis = dloadGuard.analyzeDownloadName(filename, mime);
  if (analysis.decision === dloadGuard.DECISION.REJECT) {
    return verdict(ACTION.BLOCK, 'name-rejected', {
      reasons: analysis.risks.map((r) => r.message),
      analysis,
    });
  }

  const ext = analysis.finalExt || extOfName(filename);
  const container = containerGuard.classifyContainer(filename);
  const fromWeb = hostUrl != null ? quarantine.isWebDownload(hostUrl) : false;
  const containerDecision = hostUrl == null
    ? (container.kind === containerGuard.KIND_NONE ? containerGuard.RISK_ALLOW : containerGuard.RISK_CONFIRM)
    : containerGuard.openContainerDecision({ filename, fromWeb });

  if (LOCAL_WEB_EXTS.has(ext)) {
    return verdict(ACTION.REVEAL, 'local-web-file', { reasons: analysis.risks.map((r) => r.message), analysis });
  }

  if (MOUNTABLE_EXTS.has(ext) && containerDecision !== containerGuard.RISK_ALLOW) {
    return verdict(ACTION.REVEAL, 'mountable-image', {
      reasons: [containerGuard.describeContainerRisk(container)],
      analysis,
    });
  }

  if (analysis.decision === dloadGuard.DECISION.CONFIRM ||
      analysis.isExecutable ||
      quarantine.openDecision({ filePath, hostUrl }) === 'confirm' ||
      containerDecision === containerGuard.RISK_CONFIRM) {
    const reasons = analysis.risks.map((r) => r.message);
    const containerAdvice = containerGuard.describeContainerRisk(container);
    if (containerAdvice) reasons.push(containerAdvice);
    return verdict(ACTION.CONFIRM, 'needs-confirmation', { reasons, analysis });
  }

  if (containerDecision === containerGuard.RISK_WARN) {
    return verdict(ACTION.CONFIRM, 'container-from-web', {
      reasons: [containerGuard.describeContainerRisk(container)].filter(Boolean),
      analysis,
    });
  }

  return verdict(ACTION.OPEN, 'plain-file', { analysis });
}

module.exports = {
  ACTION,
  LOCAL_WEB_EXTS,
  MOUNTABLE_EXTS,
  extOfName,
  decideOpenTarget,
};
