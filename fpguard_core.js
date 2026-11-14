'use strict';
const { isObj } = require('./modutil_core');

const { hostOf } = require('./fpguard_rules_core');

// createFingerprintLedger 建一个按“主机 + 类别”聚合的有界台账。
// category ∈ client-hints / ad-signals / ping / accept-ch。
function createFingerprintLedger(limit) {
  const max = Number.isInteger(limit) && limit > 0 ? limit : 500;
  const rows = new Map(); // key -> row

  function keyFor(host, category) {
    return host + '\u0000' + category;
  }

  function record(host, category, signals) {
    const h = String(host || '').slice(0, 255);
    const cat = String(category || 'unknown').slice(0, 32);
    if (!h) return null;
    const key = keyFor(h, cat);
    const row = rows.get(key) || { host: h, category: cat, hits: 0, signals: new Set(), lastTime: 0 };
    row.hits += 1;
    row.lastTime = Date.now();
    if (Array.isArray(signals)) {
      for (const s of signals) {
        const v = String(s || '').slice(0, 64);
        if (v) row.signals.add(v);
      }
    }
    rows.set(key, row);
    if (rows.size > max) {
      // 淘汰最久未命中的一条，给高活跃主机让位。
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, r] of rows) {
        if (r.lastTime < oldestTime) { oldestTime = r.lastTime; oldestKey = k; }
      }
      if (oldestKey !== null) rows.delete(oldestKey);
    }
    return row;
  }

  function toJSON() {
    return {
      version: 1,
      rows: [...rows.values()].map((r) => ({
        host: r.host,
        category: r.category,
        hits: r.hits,
        lastTime: r.lastTime,
        signals: [...r.signals].sort(),
      })),
    };
  }

  function load(data) {
    rows.clear();
    if (!isObj(data) || !Array.isArray(data.rows)) return;
    for (const r of data.rows) {
      if (!isObj(r) || typeof r.host !== 'string') continue;
      const row = {
        host: r.host.slice(0, 255),
        category: String(r.category || 'unknown').slice(0, 32),
        hits: Number(r.hits) || 1,
        lastTime: Number(r.lastTime) || Date.now(),
        signals: new Set(),
      };
      if (Array.isArray(r.signals)) {
        for (const s of r.signals) row.signals.add(String(s).slice(0, 64));
      }
      rows.set(keyFor(row.host, row.category), row);
    }
  }

  function stats() {
    let hits = 0;
    const byCategory = { 'client-hints': 0, 'ad-signals': 0, ping: 0, 'accept-ch': 0 };
    for (const r of rows.values()) {
      hits += r.hits;
      byCategory[r.category] = (byCategory[r.category] || 0) + r.hits;
    }
    return { hosts: rows.size, hits, byCategory };
  }

  function entries() {
    return [...rows.values()]
      .map((r) => ({
        host: r.host,
        category: r.category,
        hits: r.hits,
        lastTime: r.lastTime,
        signals: [...r.signals].sort(),
      }))
      .sort((a, b) => b.lastTime - a.lastTime);
  }

  function clear() { rows.clear(); }
  function size() { return rows.size; }

  return { record, toJSON, load, stats, entries, clear, size, hostOf };
}

module.exports = { createFingerprintLedger, ...require('./fpguard_rules_core') };
