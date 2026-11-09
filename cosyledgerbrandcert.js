'use strict';
let d = {};
function bindDeps(x) {
  d = x;
}
function persistBrandSpoofs() {
  if (d.brandSpoofSaveTimer) clearTimeout(d.brandSpoofSaveTimer);
  d.brandSpoofSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.brandSpoofStorePath, { version: 1, savedAt: Date.now(), hosts: d.brandSpoofs });
    } catch {}
  }, 5000);
}
function listBrandSpoofEntries(limit = 200) {
  d.loadBrandSpoofs();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_BRAND_SPOOF_HOSTS));
  return d.brandSpoofs.slice(-n).reverse().map(h => ({ ...h }));
}
function getBrandSpoofStats() {
  d.loadBrandSpoofs();
  const byReason = {
    'typo-domain': 0,
    'brand-in-subdomain': 0,
    'brand-keyword-impersonation': 0,
    'url-structural': 0,
  };
  const brands = new Set();
  for (const h of d.brandSpoofs) {
    if (byReason[h.reason] === undefined) byReason[h.reason] = 0;
    byReason[h.reason] += 1;
    if (h.brand) brands.add(h.brand);
  }
  return { hosts: d.brandSpoofs.length, byReason, distinctBrands: brands.size };
}
function clearBrandSpoofs() {
  d.loadBrandSpoofs();
  d.brandSpoofs = [];
  try { d.fsSync.unlinkSync(d.brandSpoofStorePath); } catch {}
  persistBrandSpoofs();
  return true;
}
function loadClientCertChoices() {
  if (d.clientCertStoreLoaded) return;
  d.clientCertStoreLoaded = true;
  try {
    // 有界文本读：clientCert 台账缺失时 readBoundedText 返回 {missing}，不解析、不加载；
    // 被塞成巨值或损坏则交由外层 try/catch / loadJSON 容错，绝不整读撑爆主进程。
    const picked = d.ledgerStore.readBoundedText(d.clientCertStorePath);
    if (!picked.missing) d.clientCertStore.loadJSON(picked.text);
  } catch {}
}
function persistClientCertChoices() {
  if (d.clientCertSaveTimer) clearTimeout(d.clientCertSaveTimer);
  d.clientCertSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.clientCertStorePath, d.clientCertStore.toJSON());
    } catch {}
  }, 300);
}
function rejectAuthChallenge(nonce) {
  const c = d.pendingAuthChallenges.get(nonce);
  if (!c) return false;
  clearTimeout(c.timer);
  d.pendingAuthChallenges.delete(nonce);
  d.failAuthCallback(c.callback);
  return true;
}
function getClientCertChoiceStats() {
  const entries = d.clientCertStore.list();
  return { count: entries.length, max: d.netAuthGuard.MAX_REMEMBERED_CERT_HOSTS };
}

module.exports = { bindDeps, persistBrandSpoofs, listBrandSpoofEntries, getBrandSpoofStats, clearBrandSpoofs, loadClientCertChoices, persistClientCertChoices, rejectAuthChallenge, getClientCertChoiceStats };
