'use strict';
let d = {};
function bindDeps(x) {
  d = x;
}
function setupNetworkStatus() {
  const report = () => {
    d.sendToRenderer('network-status-changed', { online: d.net.isOnline() });
  };
  d.app.on('online', report);
  d.app.on('offline', report);
  // 启动时先报一次当前状态
  setTimeout(report, 500);
}
function setupSystemEventGuards() {
  d.app.on('gpu-process-crashed', (_event, killed) => {
    try {
      const v = d.gpuAccessGuard.decideGPUCrash(d.gpuCrashState, { killed: !!killed }, Date.now());
      if (v.action !== d.gpuAccessGuard.ACTION_RECORD) return;
      d.recordSecurityEvent('gpu-process-crashed', 'warn', v.detail, '');
      try {
        d.sendToRenderer('gpu-process-gone', { reason: v.killed ? 'killed' : 'crashed' });
        if (d.mainWindow && !d.mainWindow.isDestroyed()) {
          d.sendToRenderer('show-toast',
            v.killed ? 'GPU 进程被系统终止，如画面异常请按 Ctrl+R 重载'
                     : 'GPU 进程崩溃已自动恢复，如画面异常请按 Ctrl+R 重载');
        }
      } catch {}
    } catch (err) {
      d.recordSecurityEvent('gpu-process-crashed', 'info',
        `GPU 崩溃守卫异常: ${String((err && err.message) || err)}`, '');
    }
  });

  d.app.on('gpu-info-update', () => {
    const now = Date.now();
    if (d.gpuInfoLastReport >= 0 && now - d.gpuInfoLastReport < d.GPU_INFO_REPORT_COOLDOWN_MS) return;
    // 用 basic 信息（含 auxAttributes），避免 'complete' 触发可能较慢的完整枚举。
    Promise.resolve()
      .then(() => (typeof d.app.getGPUInfo === 'function' ? d.app.getGPUInfo('basic') : null))
      .then((info) => {
        const clean = d.gpuAccessGuard.sanitizeGPUInfo(info && info.auxAttributes);
        if (clean.kept === 0) return;
        d.gpuInfoLastReport = Date.now();
        if (clean.fields.softwareRendering === true) {
          d.recordSecurityEvent('gpu-info-update', 'warn',
            'GPU 被重新枚举且当前回退到软件渲染（硬件加速可能不可用）', '');
        } else {
          d.recordSecurityEvent('gpu-info-update', 'info',
            'GPU 信息已更新（硬件加速生效）', '');
        }
      })
      .catch(() => {});
  });

  d.app.on('accessibility-support-changed', (_event, enabled) => {
    try {
      const v = d.gpuAccessGuard.decideAccessibilityChange(enabled);
      if (v.shouldRecord) {
        d.recordSecurityEvent('accessibility-changed', 'info', v.detail, '');
      }
    } catch {}
  });
}
function setupExtraSessionHardening() {
  return require('./sessionhardening_core').setupExtraSessionHardening(d.setupExtraSessionHardeningCtx, );
}

module.exports = { bindDeps, setupNetworkStatus, setupSystemEventGuards, setupExtraSessionHardening };
