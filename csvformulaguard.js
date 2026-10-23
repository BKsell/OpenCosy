'use strict'

// csvformulaguard.js —— 导出/导出预览 CSV 时的公式注入（CSV Injection）守卫。
//
// 威胁模型：
//   浏览器"导出下载历史 / 书签 / 表单结果为 CSV"，用户用 Excel/WPS 打开。攻击者控制的某个字段以
//   = + - @ 开头（如 =HYPERLINK("http://evil","点我")、=cmd|... ）会被当公式执行，触发外联或本地
//   命令。Tab(\t)、CR 也能在某些版本里把公式藏到看起来无害的文本后。
//   本模块：审计单元格是否以公式引导符开头，并提供 sanitizeCell（前缀单引号）与 CSV 行组装。
//   纯字符处理，不使用正则。

const CSV_REASON = Object.freeze({
  FORMULA_PREFIX: 'csv-cell-begins-with-formula-trigger',
  LEADING_TAB: 'csv-cell-begins-with-tab',
  CONTROL_CHAR: 'csv-cell-contains-control-character'
})

const TRIGGERS = ['=', '+', '-', '@', '\t', '\r']

function csvAuditCell (cell) {
  const s = String(cell)
  const findings = []
  if (s.length > 0) {
    const first = s[0]
    if (first === '=' || first === '+' || first === '-' || first === '@') {
      findings.push({ reason: CSV_REASON.FORMULA_PREFIX })
    }
    if (first === '\t') findings.push({ reason: CSV_REASON.LEADING_TAB })
    if (first === '\r') findings.push({ reason: CSV_REASON.CONTROL_CHAR })
  }
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 && c !== 0x09 && c !== 0x0A && c !== 0x0D) {
      findings.push({ reason: CSV_REASON.CONTROL_CHAR })
      break
    }
  }
  return { safe: findings.length === 0, findings: findings, triggerUsed: TRIGGERS }
}

// 以单引号中和公式引导；同时把内部 CR/制表位等保留但对引号字段转义。
function sanitizeCell (cell) {
  let s = String(cell)
  if (s.length > 0) {
    const first = s[0]
    if (first === '=' || first === '+' || first === '-' || first === '@' || first === '\t' || first === '\r') {
      s = "'" + s
    }
  }
  return s
}

// 标准 CSV 引号转义：含逗号/引号/换行则用双引号包裹，内部引号双写。
function quoteCell (cell) {
  const s = sanitizeCell(cell)
  let needQuote = false
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (ch === ',' || ch === '"' || ch === '\n' || ch === '\r') {
      needQuote = true
      break
    }
  }
  if (!needQuote) return s
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"') out += '""'
    else out += s[i]
  }
  return out + '"'
}

function buildRow (cells) {
  return cells.map(quoteCell).join(',')
}

class CsvFormulaGuard {
  auditCell (cell) {
    return csvAuditCell(cell)
  }

  sanitizeCell (cell) {
    return sanitizeCell(cell)
  }

  buildRow (cells) {
    return buildRow(cells)
  }
}

module.exports = Object.freeze({
  CSV_REASON: CSV_REASON,
  sanitizeCell: sanitizeCell,
  quoteCell: quoteCell,
  buildRow: buildRow,
  CsvFormulaGuard: CsvFormulaGuard
})
