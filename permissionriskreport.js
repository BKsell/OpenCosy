const RISK_WEIGHT = {
  media: 3,
  'clipboard-read': 3,
  midiSysex: 3,
  geolocation: 2,
  midi: 1,
  notifications: 1,
};

const LEVEL = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const STATE = { ALLOW: 'allow', DENY: 'deny', EXPIRED: 'expired', UNKNOWN: 'unknown' };
const MAX_ROWS = 200;

function weightOf(permission) {
  return RISK_WEIGHT[permission] || 0;
}

function levelForScore(score) {
  if (score >= 6) {
    return LEVEL.HIGH;
  }
  if (score >= 3) {
    return LEVEL.MEDIUM;
  }
  return LEVEL.LOW;
}

function recommendationFor(level, permissions) {
  if (level === LEVEL.HIGH) {
    return `撤销 ${permissions.join(' / ')} 中不再需要的授权`;
  }
  if (level === LEVEL.MEDIUM) {
    return '按需降级或缩短这些授权的有效期';
  }
  return '保持现状，定期复查';
}

function emptyRow(origin) {
  return {
    origin,
    allowed: [],
    denied: [],
    expired: [],
    riskScore: 0,
    level: LEVEL.LOW,
    recommendation: '',
  };
}

function buildPermissionReport(decisions, options = {}) {
  const list = Array.isArray(decisions) ? decisions : [];
  const rows = new Map();
  let skipped = 0;
  for (const decision of list) {
    if (!decision || typeof decision !== 'object') {
      skipped += 1;
      continue;
    }
    const origin = typeof decision.origin === 'string' ? decision.origin.trim() : '';
    const permission = typeof decision.permission === 'string' ? decision.permission.trim() : '';
    if (!origin || !permission) {
      skipped += 1;
      continue;
    }
    const row = rows.get(origin) || emptyRow(origin);
    const state = String(decision.state || (decision.decision === 'deny' ? STATE.DENY : STATE.ALLOW));
    if (state === STATE.DENY) {
      row.denied.push(permission);
    } else if (state === STATE.EXPIRED) {
      row.expired.push(permission);
    } else {
      row.allowed.push(permission);
    }
    rows.set(origin, row);
  }
  const result = [];
  for (const row of rows.values()) {
    row.allowed.sort();
    row.denied.sort();
    row.expired.sort();
    row.riskScore = row.allowed.reduce((sum, permission) => sum + weightOf(permission), 0);
    row.level = levelForScore(row.riskScore);
    row.recommendation = recommendationFor(row.level, row.allowed);
    result.push(row);
  }
  result.sort((a, b) => {
    if (b.riskScore !== a.riskScore) {
      return b.riskScore - a.riskScore;
    }
    return a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0;
  });
  const limit = Number.isInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, MAX_ROWS) : MAX_ROWS;
  const totals = {
    origins: rows.size,
    decisions: list.length - skipped,
    skipped,
    allowed: result.reduce((sum, row) => sum + row.allowed.length, 0),
    denied: result.reduce((sum, row) => sum + row.denied.length, 0),
    expired: result.reduce((sum, row) => sum + row.expired.length, 0),
    highRiskOrigins: result.filter((row) => row.level === LEVEL.HIGH).length,
    mediumRiskOrigins: result.filter((row) => row.level === LEVEL.MEDIUM).length,
  };
  return { totals, rows: result.slice(0, limit), truncated: result.length > limit };
}

function topRiskyOrigins(report, count = 5) {
  if (!report || !Array.isArray(report.rows)) {
    return [];
  }
  const n = Number.isInteger(count) && count > 0 ? count : 5;
  return report.rows.filter((row) => row.riskScore > 0).slice(0, n).map((row) => row.origin);
}

function describePermissionReport(report) {
  if (!report || !report.totals) {
    return '站点权限风险报告不可用';
  }
  const totals = report.totals;
  const head = `覆盖 ${totals.origins} 个站点、${totals.decisions} 条授权记录`;
  const risky = topRiskyOrigins(report, 3);
  if (risky.length === 0) {
    return `${head}，未发现高危授权`;
  }
  return `${head}，${totals.highRiskOrigins} 个高危站点，优先处理 ${risky.join('、')}`;
}

function needsAttention(report) {
  if (!report || !report.totals) {
    return false;
  }
  return report.totals.highRiskOrigins > 0 || report.totals.expired > 0;
}

module.exports = {
  RISK_WEIGHT,
  LEVEL,
  MAX_ROWS,
  buildPermissionReport,
  describePermissionReport,
  topRiskyOrigins,
  needsAttention,
};
