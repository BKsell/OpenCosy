'use strict';
const { describeReasonTable } = require('./reasontext');

const REASON = Object.freeze({
  OK: 'ok',
  LEGACY_OBJECT: 'legacy-object',
  FLASH_CONTENT: 'flash-content',
  DATA_OBJECT: 'data-object',
  INTERNAL_ALLOWED: 'internal-allowed',
});

const PLUGIN_RESOURCE_TYPES = new Set(['object', 'plugin']);

function isInternalUrl(url) {
  return typeof url === 'string' && url.startsWith('cosy:');
}

function isFlashUrl(url) {
  if (typeof url !== 'string') return false;
  const lower = url.toLowerCase();
  if (lower.endsWith('.swf')) return true;
  return lower.includes('.swf?') || lower.includes('.swf#');
}

function evaluatePluginResource(input = {}) {
  const url = typeof input.url === 'string' ? input.url : '';
  const resourceType = typeof input.resourceType === 'string' ? input.resourceType.toLowerCase() : '';

  if (isInternalUrl(url)) {
    return { action: 'allow', reason: REASON.INTERNAL_ALLOWED, detail: '内置 cosy: 资源不受插件守卫限制' };
  }
  if (isFlashUrl(url)) {
    return { action: 'cancel', reason: REASON.FLASH_CONTENT, detail: 'Flash 内容已被浏览器淘汰且历史上漏洞密集' };
  }
  if (PLUGIN_RESOURCE_TYPES.has(resourceType)) {
    if (url.startsWith('data:')) {
      return { action: 'cancel', reason: REASON.DATA_OBJECT, detail: 'object/embed 加载 data: 内容' };
    }
    return { action: 'cancel', reason: REASON.LEGACY_OBJECT, detail: `禁止加载 ${resourceType} 类型的外部插件内容` };
  }
  return { action: 'allow', reason: REASON.OK, detail: '' };
}

const REASON_TEXT = {
  [REASON.OK]: '非插件资源',
  [REASON.LEGACY_OBJECT]: '旧式 object/embed 插件内容',
  [REASON.FLASH_CONTENT]: 'Flash 内容',
  [REASON.DATA_OBJECT]: 'data: 插件内容',
  [REASON.INTERNAL_ALLOWED]: '内置资源放行',
};

const describeReason = describeReasonTable(REASON_TEXT, '未知原因');

module.exports = {
  REASON,
  PLUGIN_RESOURCE_TYPES,
  evaluatePluginResource,
  describeReason,
};
