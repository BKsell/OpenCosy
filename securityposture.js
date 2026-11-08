const GRADE_ORDER = ['A', 'B', 'C', 'D', 'F'];

const SEVERITY = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

function toCount(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return 0;
  }
  return Math.floor(n);
}

function gradeIndex(grade) {
  const idx = GRADE_ORDER.indexOf(String(grade || '').toUpperCase());
  return idx < 0 ? GRADE_ORDER.length - 1 : idx;
}

function weakHeaderCount(distribution) {
  if (!distribution || typeof distribution !== 'object') {
    return 0;
  }
  let weak = 0;
  for (const [grade, count] of Object.entries(distribution)) {
    if (gradeIndex(grade) >= 2) {
      weak += toCount(count);
    }
  }
  return weak;
}

function collectFindings(input) {
  const findings = [];
  if (!input.httpsOnly) {
    findings.push({
      id: 'https-only-off',
      severity: SEVERITY.HIGH,
      penalty: 28,
      message: 'HTTPS-only 未开启，明文导航与降级链仍然可达',
    });
  }
  if (toCount(input.certExceptions) > 0) {
    findings.push({
      id: 'cert-exceptions',
      severity: SEVERITY.HIGH,
      penalty: 18,
      message: `存在 ${toCount(input.certExceptions)} 条证书例外，TLS 信任被局部削弱`,
    });
  }
  if (toCount(input.riskyOrigins) > 0) {
    findings.push({
      id: 'risky-permissions',
      severity: SEVERITY.HIGH,
      penalty: 18,
      message: `${toCount(input.riskyOrigins)} 个站点叠加了多项高危权限`,
    });
  }
  if (toCount(input.criticalEvents) > 0) {
    findings.push({
      id: 'critical-events',
      severity: SEVERITY.HIGH,
      penalty: 16,
      message: `安全事件日志里有 ${toCount(input.criticalEvents)} 条 critical 记录未清理`,
    });
  }
  if (toCount(input.cspReports) >= 5) {
    findings.push({
      id: 'csp-noise',
      severity: SEVERITY.MEDIUM,
      penalty: 10,
      message: `CSP 违规报告累积到 ${toCount(input.cspReports)} 条，页面策略可能需要收紧`,
    });
  }
  const weak = weakHeaderCount(input.headerGrades);
  if (weak > 0) {
    findings.push({
      id: 'weak-headers',
      severity: SEVERITY.MEDIUM,
      penalty: Math.min(14, weak * 2),
      message: `${weak} 个站点缺少必要的安全响应头`,
    });
  }
  if (toCount(input.blockRules) === 0) {
    findings.push({
      id: 'no-block-rules',
      severity: SEVERITY.LOW,
      penalty: 5,
      message: '尚未配置任何拦截规则，跟踪器与广告域不受限制',
    });
  }
  if (toCount(input.expiredGrants) > 0) {
    findings.push({
      id: 'expired-grants',
      severity: SEVERITY.LOW,
      penalty: Math.min(8, toCount(input.expiredGrants)),
      message: `有 ${toCount(input.expiredGrants)} 条过期授权等待清理`,
    });
  }
  return findings;
}

function gradeForScore(score) {
  if (score >= 90) {
    return 'A';
  }
  if (score >= 75) {
    return 'B';
  }
  if (score >= 60) {
    return 'C';
  }
  if (score >= 40) {
    return 'D';
  }
  return 'F';
}

function scorePosture(input = {}) {
  const findings = collectFindings(input);
  const penalty = findings.reduce((sum, item) => sum + item.penalty, 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));
  return {
    score,
    grade: gradeForScore(score),
    findings,
    summary: {
      httpsOnly: Boolean(input.httpsOnly),
      blockRules: toCount(input.blockRules),
      cspReports: toCount(input.cspReports),
      certExceptions: toCount(input.certExceptions),
      riskyOrigins: toCount(input.riskyOrigins),
      criticalEvents: toCount(input.criticalEvents),
      weakHeaderSites: weakHeaderCount(input.headerGrades),
      expiredGrants: toCount(input.expiredGrants),
    },
  };
}

function describePosture(report) {
  if (!report || !Array.isArray(report.findings)) {
    return '安全态势不可用';
  }
  const head = `安全态势评分 ${report.score}/100（${report.grade} 级）`;
  if (report.findings.length === 0) {
    return `${head}，未发现需要处理的问题`;
  }
  const items = report.findings.map((f) => `[${f.severity}] ${f.message}`);
  return `${head}：${items.join('；')}`;
}

function worstSeverity(report) {
  if (!report || !Array.isArray(report.findings) || report.findings.length === 0) {
    return 'none';
  }
  let worst = 'none';
  for (const finding of report.findings) {
    if (finding.severity === SEVERITY.HIGH) {
      return SEVERITY.HIGH;
    }
    if (finding.severity === SEVERITY.MEDIUM) {
      worst = SEVERITY.MEDIUM;
    } else if (worst === 'none' && finding.severity === SEVERITY.LOW) {
      worst = SEVERITY.LOW;
    }
  }
  return worst;
}

module.exports = { SEVERITY, GRADE_ORDER, scorePosture, describePosture, worstSeverity };
