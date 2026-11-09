'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function recordBrandSpoof(hit) {
  try {
    if (!hit || typeof hit !== 'object') return;
    const host = String(hit.hostname || '').toLowerCase().replace(/\.$/, '').slice(0, 253);
    if (!host || !d.BRAND_SPOOF_REASONS.has(hit.reason)) return;
    const now = Date.now();
    loadBrandSpoofs();
    const idx = d.brandSpoofs.findIndex(h => h.host === host);
    if (idx >= 0) {
      const rec = d.brandSpoofs[idx];
      rec.lastTime = now;
      rec.count = Math.min(Number.MAX_SAFE_INTEGER, (Number(rec.count) || 1) + 1);
      // 最近一次的原因/品牌更可信（同一主机可能命中多条规则）。
      rec.reason = hit.reason;
      rec.brand = String(hit.brand || rec.brand || '').slice(0, 40);
      rec.hint = String(hit.hint || rec.hint || '').slice(0, 120);
      d.brandSpoofs.splice(idx, 1);
      d.brandSpoofs.push(rec);
    } else {
      d.brandSpoofs.push({
        host,
        brand: String(hit.brand || '').slice(0, 40),
        reason: hit.reason,
        hint: String(hit.hint || '').slice(0, 120),
        firstTime: now,
        lastTime: now,
        count: 1,
      });
    }
    if (d.brandSpoofs.length > d.MAX_BRAND_SPOOF_HOSTS) {
      d.brandSpoofs.splice(0, d.brandSpoofs.length - d.MAX_BRAND_SPOOF_HOSTS);
    }
    persistBrandSpoofs();
    if (d.brandSpoofNotifyTimer) return;
    d.brandSpoofNotifyTimer = setTimeout(() => {
      d.brandSpoofNotifyTimer = null;
      sendToRenderer('brand-spoof-updated', getBrandSpoofStats());
    }, 2000);
    d.brandSpoofNotifyTimer.unref?.();
  } catch {}
}

function recordRequestAttempt(details, blocked) {
  try {
    if (!details || typeof details.url !== 'string') return;
    if (!/^https?:/i.test(details.url)) return;
    loadRequestLog();
    d.requestLog.ingest(d.requestLogStore, {
      url: details.url,
      resourceType: details.resourceType,
      blocked: !!blocked,
      navigated: !blocked && details.resourceType === 'mainFrame',
      time: Date.now(),
    });
    persistRequestLog();
    if (d.requestLogNotifyTimer) return;
    d.requestLogNotifyTimer = setTimeout(() => {
      d.requestLogNotifyTimer = null;
      sendToRenderer('request-log-updated', d.requestLog.stats(d.requestLogStore));
    }, 2000);
    d.requestLogNotifyTimer.unref?.();
  } catch {}
}

function recordHeaderGrade(url, rawHeaders) {
  if (typeof url !== 'string' || !/^https?:/i.test(url)) return;
  let result;
  try {
    result = d.headerGrade.gradeSecurityHeaders(url, rawHeaders);
  } catch {
    return;
  }
  if (!result || !result.host) return;
  loadHeaderGrades();
  const now = Date.now();
  const idx = d.headerGrades.findIndex(h => h.host === result.host);
  const record = {
    host: result.host,
    time: now,
    visits: 1,
    grade: result.grade,
    percent: result.percent,
    insecureTransport: !!result.insecureTransport,
    checks: result.checks.map(c => ({
      id: String(c.id), name: String(c.name), weight: Number(c.weight) || 0,
      score: Number(c.score) || 0, status: String(c.status),
      value: String(c.value || '').slice(0, 300), note: String(c.note || '').slice(0, 300),
    })),
    warnings: result.warnings.map(w => String(w).slice(0, 200)).slice(0, 16),
  };
  if (idx >= 0) {
    record.visits = Math.min(Number.MAX_SAFE_INTEGER, (Number(d.headerGrades[idx].visits) || 1) + 1);
    d.headerGrades.splice(idx, 1);
    d.headerGrades.push(record);
  } else {
    d.headerGrades.push(record);
  }
  if (d.headerGrades.length > d.MAX_HEADER_GRADE_HOSTS) {
    d.headerGrades.splice(0, d.headerGrades.length - d.MAX_HEADER_GRADE_HOSTS);
  }
  persistHeaderGrades();
  sendToRenderer('header-grade-updated', { host: record.host, grade: record.grade, percent: record.percent });
}

function recordFpHit(host, category, signals) {
  if (!host) return;
  loadFpLedger();
  d.fpLedger.record(host, category, signals);
  persistFpLedger();
  sendToRenderer('fingerprint-blocked-updated', d.fpLedger.stats());
}

function loadBrandSpoofs() {
  if (d.brandSpoofsLoaded) return;
  d.brandSpoofsLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.brandSpoofStorePath, {});
    if (data && Array.isArray(data.hosts)) {
      const now = Date.now();
      for (const h of data.hosts) {
        if (!h || typeof h !== 'object') continue;
        if (typeof h.host !== 'string' || !h.host) continue;
        if (!d.BRAND_SPOOF_REASONS.has(h.reason)) continue;
        d.brandSpoofs.push({
          host: String(h.host).slice(0, 253),
          brand: String(h.brand || '').slice(0, 40),
          reason: h.reason,
          hint: String(h.hint || '').slice(0, 120),
          firstTime: Number(h.firstTime) || now,
          lastTime: Number(h.lastTime) || now,
          count: Math.max(1, Number(h.count) || 1),
        });
      }
      if (d.brandSpoofs.length > d.MAX_BRAND_SPOOF_HOSTS) {
        d.brandSpoofs = d.brandSpoofs.slice(-d.MAX_BRAND_SPOOF_HOSTS);
      }
    }
  } catch {}
}

function loadHeaderGrades() {
  if (d.headerGradesLoaded) return;
  d.headerGradesLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.headerGradeStorePath, {});
    const entries = Array.isArray(data && data.hosts) ? data.hosts : null;
    if (!entries) return;
    for (const h of entries) {
      if (!h || typeof h !== 'object' || typeof h.host !== 'string' || !h.host) continue;
      if (typeof h.grade !== 'string' || !/^[A-F]$/.test(h.grade)) continue;
      d.headerGrades.push({
        host: h.host.slice(0, 253),
        time: Number(h.time) || Date.now(),
        visits: Math.max(1, Number(h.visits) || 1),
        grade: h.grade,
        percent: Math.max(0, Math.min(100, Number(h.percent) || 0)),
        insecureTransport: !!h.insecureTransport,
        checks: Array.isArray(h.checks) ? h.checks.slice(0, 16) : [],
        warnings: Array.isArray(h.warnings) ? h.warnings.slice(0, 16) : [],
      });
      if (d.headerGrades.length >= d.MAX_HEADER_GRADE_HOSTS) break;
    }
  } catch {}
}

module.exports = { recordBrandSpoof, recordRequestAttempt, recordHeaderGrade, recordFpHit, loadBrandSpoofs, loadHeaderGrades, bindDeps };
