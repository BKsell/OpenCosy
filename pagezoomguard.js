'use strict';

const REASON = {
  ZOOM_OUT_OF_RANGE: 'zoom-out-of-range',
  ZOOM_SITE_HOST_EMPTY: 'zoom-site-host-empty',
  ZOOM_SITE_WILDCARD: 'zoom-site-wildcard',
  ZOOM_SITE_TRAVERSAL: 'zoom-site-traversal',
  ZOOM_SITE_LIMIT: 'zoom-site-limit',
  ZOOM_SITE_DUPLICATE: 'zoom-site-duplicate',
};

const LIMITS = {
  MIN_ZOOM: 50,
  MAX_ZOOM: 300,
  MAX_SITES: 200,
};

function pick(source, path) {
  let current = source;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function evaluatePageZoomGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const zoom_out_of_rangeValue = Number(pick(data, 'zoom'));
  if (Number.isFinite(zoom_out_of_rangeValue) && (zoom_out_of_rangeValue < 50 || zoom_out_of_rangeValue > 300)) {
    add(REASON.ZOOM_OUT_OF_RANGE, '缩放比例超出安全区间', false);
  }

  const zoom_site_host_emptyList = Array.isArray(pick(data, 'sites')) ? pick(data, 'sites') : [];
  if (zoom_site_host_emptyList.some((item) => !item || !String(item.host || '').trim())) {
    add(REASON.ZOOM_SITE_HOST_EMPTY, '按站点缩放存在空主机名', true);
  }

  const zoom_site_wildcardList = Array.isArray(pick(data, 'sites')) ? pick(data, 'sites') : [];
  const zoom_site_wildcardHit = zoom_site_wildcardList.some((item) => new RegExp('\\*').test(String((item && typeof item === 'object' ? item.host : item) || '')));
  if (zoom_site_wildcardHit) {
    add(REASON.ZOOM_SITE_WILDCARD, '按站点缩放不允许通配主机', true);
  }

  const zoom_site_traversalList = Array.isArray(pick(data, 'sites')) ? pick(data, 'sites') : [];
  const zoom_site_traversalHit = zoom_site_traversalList.some((item) => new RegExp('\\.\\.|/|\\\\').test(String((item && typeof item === 'object' ? item.host : item) || '')));
  if (zoom_site_traversalHit) {
    add(REASON.ZOOM_SITE_TRAVERSAL, '站点主机名包含路径穿越字符', true);
  }

  const zoom_site_limitList = Array.isArray(pick(data, 'sites')) ? pick(data, 'sites') : [];
  if (zoom_site_limitList.length > 200) {
    add(REASON.ZOOM_SITE_LIMIT, '按站点缩放记录超出上限', false);
  }

  const zoom_site_duplicateList = Array.isArray(pick(data, 'sites')) ? pick(data, 'sites') : [];
  const zoom_site_duplicateSeen = new Set();
  let zoom_site_duplicateDup = false;
  for (const item of zoom_site_duplicateList) {
    const marker = String((item && typeof item === 'object' ? item.host : item) || '').toLowerCase();
    if (!marker) continue;
    if (zoom_site_duplicateSeen.has(marker)) zoom_site_duplicateDup = true;
    zoom_site_duplicateSeen.add(marker);
  }
  if (zoom_site_duplicateDup) {
    add(REASON.ZOOM_SITE_DUPLICATE, '同一主机名重复配置缩放', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePageZoomGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePageZoomGuard, describePageZoomGuard };
