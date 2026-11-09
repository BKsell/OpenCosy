'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

async function executeCleanPlan(plan) {
  if (!plan || typeof plan !== 'object') return { ok: false, reason: 'bad-plan' };
  if (!Array.isArray(plan.actions) || plan.actions.length === 0) return { ok: false, reason: 'bad-plan' };
  const src = enumerateSiteStorage();
  const filtered = d.cleanerCore.filterSiteEntries(src.entries, {
    matchMode: plan.mode,
    host: plan.host,
    since: plan.since,
    storageTypes: plan.storageTypes,
  });
  if (!filtered.ok) return { ...filtered };
  // 摘要核对：renderer 传来的计划（sites/targetCount/bytes）必须与 main 重算结果一致；
  // 不一致说明计划在途中被改过（或数据已变化），拒绝执行。
  if (typeof plan.sites === 'number' && filtered.sites !== plan.sites) {
    return { ok: false, reason: 'plan-mismatch', expected: filtered.sites, got: plan.sites };
  }
  if (typeof plan.targetCount === 'number' && filtered.targets.length !== plan.targetCount) {
    return { ok: false, reason: 'plan-mismatch', expected: filtered.targets.length, got: plan.targetCount };
  }
  if (typeof plan.totalBytes === 'number' && filtered.totalBytes !== plan.totalBytes) {
    return { ok: false, reason: 'plan-mismatch', expected: filtered.totalBytes, got: plan.totalBytes };
  }
  const cleaned = [];
  const failed = [];
  const storageTypes = plan.actions;
  for (const t of filtered.targets) {
    try {
      const ses = session.defaultSession;
      const origin = String(t.origin || '');
      if (origin === '') continue;
      // 按 origin + 类型做最小化清理：全部类型用 clearStorageData({ origin })，
      // 否则逐类型调用。
      const opts = { origin };
      if (!storageTypes.includes('all')) {
        const mapped = storageTypes.map((a) => d.cleanerCore.classifyStorageType(a))
          .filter((a) => a !== '' && a !== 'all');
        if (mapped.length === 0) { failed.push({ origin, reason: 'no-actions' }); continue; }
        for (const st of mapped) {
          try {
            const res = await ses.clearStorageData({ origin, storages: [st] });
            void res;
          } catch (e) { failed.push({ origin, storageType: st, reason: String(e && e.message || e) }); }
        }
      } else {
        try {
          const res = await ses.clearStorageData({ origin });
          void res;
        } catch (e) { failed.push({ origin, reason: String(e && e.message || e) }); }
      }
      cleaned.push(t.origin);
    } catch (e) { failed.push({ origin: t.origin, reason: String(e && e.message || e) }); }
  }
  const audit = d.cleanerCore.recordCleanAudit(d.cleanAuditLog, {
    mode: filtered.mode,
    host: filtered.host,
    sites: filtered.sites,
    targetCount: filtered.targets.length,
    bytes: filtered.totalBytes,
    actions: storageTypes,
    source: 'cleaner-ui',
  });
  persistCleanAudit();
  return { ok: true, cleaned: cleaned.length, failed, audit: audit.ok ? audit.entry : null };
}

function initVaultOnStartup() {
  loadVaultStateFromDisk();
  if (!d.fsSync.existsSync(d.vaultKeyPath)) return { ok: true, unlocked: false, reason: 'no-key' };
  try {
    const raw = JSON.parse(d.fsSync.readFileSync(d.vaultKeyPath, 'utf8'));
    if (!raw || raw.v !== 1 || typeof raw.wrapped !== 'string') return { ok: true, unlocked: false };
    if (raw.s !== 'safe') {
      d.recordSecurityEvent('vault-key', 'critical',
        '保险库密钥未经系统加密保护，已拒绝自动解锁', 'vault');
      return { ok: true, unlocked: false, reason: 'untrusted-key' };
    }
    if (!safeStorage.isEncryptionAvailable()) return { ok: true, unlocked: false, reason: 'no-safe-storage' };
    const wrapped = Buffer.from(raw.wrapped, 'base64');
    const hex = safeStorage.decryptString(wrapped);
    const key = Buffer.from(hex, 'hex');
    if (key.length < d.vaultCore.MIN_MASTER_KEY_BYTES) return { ok: true, unlocked: false };
    if (!d.vaultState) return { ok: true, unlocked: false };
    const loaded = d.vaultCore.loadVault(JSON.stringify(d.vaultState), key);
    if (loaded.ok) {
      d.vaultHandle = loaded.vault;
      d.vaultUsePasswordMode = false;
      return { ok: true, unlocked: true };
    }
  } catch (e) { console.error('自动解锁保险库失败:', e); }
  return { ok: true, unlocked: false };
}

function createNewVault(masterPassword) {
  let key;
  let kdf = d.vaultCore.KDF_HKDF;
  d.vaultUsePasswordMode = false;
  if (typeof masterPassword === 'string' && masterPassword.length > 0) {
    key = Buffer.from(masterPassword, 'utf8');
    kdf = d.vaultCore.KDF_PBKDF2;
    d.vaultUsePasswordMode = true;
  } else {
    if (!safeStorage.isEncryptionAvailable()) {
      d.recordSecurityEvent('vault-key', 'critical',
        '缺少可用的系统加密，创建保险库必须设置主密码', 'vault');
      return { ok: false, reason: 'password-required' };
    }
    key = d.crypto.randomBytes(32);
  }
  const c = d.vaultCore.createVault(key, { kdf });
  if (!c.ok) return c;
  d.vaultHandle = c.vault;
  d.vaultState = c.vault.exportState().state;
  persistVaultState();
  const keyPersisted = d.vaultUsePasswordMode ? true : persistVaultKey(key);
  return { ok: true, keyPersisted, ...vaultStatusSnapshot() };
}

function unlockVault(masterPassword) {
  if (typeof masterPassword !== 'string' || masterPassword === '') {
    return { ok: false, reason: 'bad-password' };
  }
  if (!d.vaultState) return { ok: false, reason: 'no-vault' };
  const key = Buffer.from(masterPassword, 'utf8');
  const loaded = d.vaultCore.loadVault(JSON.stringify(d.vaultState), key);
  if (!loaded.ok) return { ok: false, reason: loaded.reason };
  d.vaultHandle = loaded.vault;
  d.vaultUsePasswordMode = true;
  return { ok: true, ...vaultStatusSnapshot() };
}

function vaultStatusSnapshot() {
  const unlocked = !!(d.vaultHandle && !d.vaultHandle.locked());
  let entries = [];
  if (unlocked) {
    const l = d.vaultHandle.list();
    if (l.ok) entries = l.entries;
  }
  return {
    ok: true,
    unlocked,
    passwordMode: d.vaultUsePasswordMode,
    storageAvailable: safeStorage.isEncryptionAvailable(),
    hasVault: !!d.vaultState,
    entries,
  };
}

function enumerateSiteStorage() {
  const out = [];
  const ses = session.defaultSession;
  // 1) clearStorageData 支持的类型无法枚举，改用 storageData 不可得；
  //    这里列出“可确认存在”的 origin 维度信息由 plan 阶段补充。
  // 2) service workers：遍历 registrations。
  try {
    const sw = ses.serviceWorkers;
    const regs = sw.getAllRunning() || {};
    for (const id of Object.keys(regs)) {
      const reg = regs[id];
      const scope = reg && reg.scope ? reg.scope : '';
      if (scope) out.push({ origin: scope, storageType: 'serviceworkers', bytes: 0, lastAccessed: Date.now() });
    }
  } catch {}
  return { ok: true, entries: out };
}

module.exports = { executeCleanPlan, initVaultOnStartup, createNewVault, unlockVault, vaultStatusSnapshot, enumerateSiteStorage, bindDeps };
