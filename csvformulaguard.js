'use strict';

const REASON = {
  OK: 'ok',
  NOT_LIST: 'not-list',
  TOO_MANY_CELLS: 'too-many-cells',
  TOO_LONG_CELL: 'too-long-cell',
  FORMULA_ESCAPED: 'formula-escaped',
  CONTROL_STRIPPED: 'control-stripped',
};

const MAX_CELLS = 100000;
const MAX_CELL_LENGTH = 32767;
const FORMULA_PREFIXES = ['=', '+', '-', '@', '\t', '\r'];
const CONTROL_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function inspectCell(value) {
  if (typeof value !== 'string') return { ok: false, reason: REASON.NOT_LIST, text: '' };
  if (value.length > MAX_CELL_LENGTH) return { ok: false, reason: REASON.TOO_LONG_CELL, text: '' };
  const cleaned = CONTROL_PATTERN.test(value) ? value.replace(CONTROL_PATTERN, '') : value;
  const first = cleaned.charAt(0);
  if (FORMULA_PREFIXES.includes(first)) {
    return { ok: true, reason: REASON.FORMULA_ESCAPED, text: "'" + cleaned, changed: true };
  }
  if (cleaned !== value) return { ok: true, reason: REASON.CONTROL_STRIPPED, text: cleaned, changed: true };
  return { ok: true, reason: REASON.OK, text: cleaned, changed: false };
}

function guardRow(cells) {
  if (!Array.isArray(cells)) return { changed: false, reason: REASON.NOT_LIST, cells: [] };
  if (cells.length > MAX_CELLS) return { changed: true, reason: REASON.TOO_MANY_CELLS, cells: [] };
  let changed = false;
  let reason = REASON.OK;
  const out = [];
  for (const cell of cells) {
    const result = inspectCell(cell);
    if (!result.ok) return { changed: true, reason: result.reason, cells: [] };
    if (result.changed) {
      changed = true;
      if (reason === REASON.OK) reason = result.reason;
    }
    out.push(result.text);
  }
  return { changed, reason, cells: out };
}

function guardMatrix(rows) {
  if (!Array.isArray(rows)) return { changed: false, reason: REASON.NOT_LIST, rows: [] };
  let changed = false;
  let reason = REASON.OK;
  const out = [];
  for (const row of rows) {
    const result = guardRow(row);
    if (result.changed) {
      changed = true;
      if (reason === REASON.OK) reason = result.reason;
    }
    out.push(result.cells);
  }
  return { changed, reason, rows: out };
}

function applyCsvFormulaGuard(rows) {
  return guardMatrix(rows);
}

function describeReason(reason) {
  switch (reason) {
    case REASON.NOT_LIST:
      return 'CSV 单元格不是列表';
    case REASON.TOO_MANY_CELLS:
      return 'CSV 行单元格数量过多';
    case REASON.TOO_LONG_CELL:
      return 'CSV 单元格内容超长';
    case REASON.FORMULA_ESCAPED:
      return 'CSV 单元格公式前缀已转义';
    case REASON.CONTROL_STRIPPED:
      return 'CSV 单元格控制字符已清除';
    default:
      return 'CSV 内容安全';
  }
}

module.exports = {
  REASON,
  MAX_CELLS,
  MAX_CELL_LENGTH,
  FORMULA_PREFIXES,
  inspectCell,
  guardRow,
  guardMatrix,
  applyCsvFormulaGuard,
  describeReason,
};
