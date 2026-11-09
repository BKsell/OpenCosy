let d = {};
function bindDeps(x) {
  d = x;
}
function noteGuardResult(label, result, url, shouldLog) {
  if (result.changed && shouldLog) {
    d.recordSecurityEvent('mixed-content-blocked', 'warn', `${label}:${result.reason}`, d.fpGuard.hostOf(url));
  }
  return result;
}
function noteGuardDenied(label, result, url, shouldLog) {
  if (!result.allowed && shouldLog) {
    d.recordSecurityEvent('mixed-content-blocked', 'warn', `${label}:${result.reason}`, d.fpGuard.hostOf(url));
  }
  return result;
}
function allowPopupForTab(tabId) {
  const now = Date.now();
  const times = (d.popupOpenTimes.get(tabId) || []).filter(t => now - t < d.POPUP_WINDOW_MS);
  if (times.length >= d.POPUP_WINDOW_MAX) {
    d.popupOpenTimes.set(tabId, times);
    return false;
  }
  times.push(now);
  d.popupOpenTimes.set(tabId, times);
  return true;
}
function getContentsState(map, id, create) {
  let st = map.get(id);
  if (!st) {
    st = create(Date.now());
    map.set(id, st);
  }
  return st;
}
function reloadCustomRules() {
  d.compiledCustomRules = d.blockRules.compileRules(d.customRules);
}
function loadCustomRulesFromDisk(filePath) {
  d.customRulesFile = filePath;
  if (!d.customRulesLoaded) {
    const loaded = d.blockRules.loadRules(filePath);
    d.customRules.host = loaded.host;
    d.customRules.glob = loaded.glob;
    d.customRules.path = loaded.path;
    d.customRulesLoaded = true;
    reloadCustomRules();
  }
}
function persistCustomRules() {
  if (!d.customRulesFile) return { ok: false, reason: 'no-file' };
  const r = d.blockRules.saveRules(d.customRulesFile, d.customRules);
  reloadCustomRules();
  return r;
}
function hostMatchesTracker(hostname) {
  return d.hostMatch.hostMatchesList(hostname, d.TRACKER_HOSTS);
}
function isTrackerRequest(details) {
  if (!d.blockTrackers) return false;
  const rt = details.resourceType;
  if (rt === 'mainFrame' || rt === 'subFrame') return false;
  let host = '';
  try { host = new URL(details.url).hostname; } catch { return false; }
  const decision = d.blockRules.decideBlocked(details.url, d.compiledCustomRules, d.TRACKER_HOSTS);
  if (decision) return true;
  return hostMatchesTracker(host);
}
function recordBlockedTracker(url) {
  d.blockedTrackerCount += 1;
  const host = d.urlResolve.safeHostname(url, '(unknown)');
  d.blockedTrackerByHost.set(host, (d.blockedTrackerByHost.get(host) || 0) + 1);
  d.sendToRenderer('trackers-blocked', {
    count: d.blockedTrackerCount,
    host,
    top: topBlockedHosts(),
  });
}
function topBlockedHosts() {
  return [...d.blockedTrackerByHost.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([host, n]) => ({ host, n }));
}
function isTrackingQueryKey(rawKey) {
  const key = String(rawKey || '').toLowerCase();
  if (!key) return false;
  if (d.TRACKING_QUERY_KEYS.has(key)) return true;
  return d.TRACKING_QUERY_PREFIXES.some(p => key.startsWith(p));
}
function stripTrackingFromUrl(rawUrl) {
  if (!d.stripTrackingParams) return null;
  if (!(rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))) return null;
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (!u.search) return null;
  const params = u.searchParams;
  let removed = false;
  // 先收集再删，避免边遍历边改。
  const keys = [];
  for (const key of params.keys()) keys.push(key);
  for (const key of keys) {
    if (isTrackingQueryKey(key)) { params.delete(key); removed = true; }
  }
  if (!removed) return null;
  const query = u.searchParams.toString();
  const rebuilt = u.origin + u.pathname + (query ? '?' + query : '') + u.hash;
  return rebuilt === rawUrl ? null : rebuilt;
}
function hostnameHasSuspiciousChars(hostname) {
  // 非 ASCII：IDN（punycode 解码后的 unicode 主机），本身不是错，但组合常见品牌词要提醒。
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(hostname)) return 'nonascii';
  // 纯拉丁里的易混对：数字/特殊形替字母（如 0 替 o、1 替 l、rn 替 m 由调用方另判）。
  if (/\d/.test(hostname)) {
    const label = hostname.split('.')[0].toLowerCase();
    if (d.SKEW_LATIN_HOSTS.has(label.replace(/[0-9]/g, ''))) return 'digit-lookalike';
  }
  return null;
}
function analyzeHostForSpoof(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase().replace(/\.$/, '');
  const labels = h.split('.');
  const registrable = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  // 含非 ASCII，且品牌主体与已知拉丁品牌高度重合（去掉非拉丁后等于某品牌）→ 高危提示。
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(registrable)) {
    const asciiOnly = registrable.replace(/[^\x21-\x7e]/g, '');
    // 混合脚本：同一主体里既有拉丁又有非拉丁，是 homograph 攻击最典型特征。
    // eslint-disable-next-line no-control-regex
    const hasLatin = /[a-z]/.test(registrable);
    const hasNonLatin = /[^\x00-\x7fa-z0-9.-]/.test(registrable);
    if (hasLatin && hasNonLatin) {
      return { reason: 'mixed-script', hostname: h, hint: asciiOnly };
    }
  }
  const suspicious = hostnameHasSuspiciousChars(h);
  if (suspicious === 'digit-lookalike') {
    return { reason: 'digit-lookalike', hostname: h, hint: registrable };
  }
  return null;
}
function originOf(u) {
  // Referer 收敛需要用 null 表达"无法解析/无同源源"，保持原语义。
  return d.urlResolve.safeOrigin(u, null);
}
module.exports = { bindDeps, noteGuardResult, noteGuardDenied, allowPopupForTab, getContentsState, reloadCustomRules, loadCustomRulesFromDisk, persistCustomRules, hostMatchesTracker, isTrackerRequest, recordBlockedTracker, topBlockedHosts, isTrackingQueryKey, stripTrackingFromUrl, hostnameHasSuspiciousChars, analyzeHostForSpoof, originOf };
