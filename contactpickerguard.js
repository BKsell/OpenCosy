'use strict';

// contactpickerguard.js —— Contact Picker API（navigator.contacts.select）通讯录过度读取裁决内核。
//
// 威胁模型：
//   1. 移动端页面可用 contacts.select(properties,{multiple}) 在用户一次"同意"后批量读取通讯录，
//      properties 里带 name/email/tel/address/icon，address/icon 是高敏项，一个营销页可拖走整本
//      联系人；
//   2. multiple:true 允许全选，返回结果无上限，造成大规模 PII 外泄；
//   3. 无手势/不可见页面弹系统联系人选择器；
//   4. 返回条目数量与字段数不受控，作为后续撞库/钓鱼数据源；
//   5. 非安全上下文调用。
//
// 纯逻辑：裁决入参字段与多选，并对返回结果做数量/字段复核。

const CP_ALLOW = 'allow';
const CP_DENY = 'deny';

const CP_REASON = Object.freeze({
  BAD_CONTEXT: 'cp-bad-context',
  INSECURE_ORIGIN: 'cp-insecure-origin',
  NO_GESTURE: 'cp-no-gesture',
  NOT_VISIBLE: 'cp-not-visible',
  NO_PROPERTIES: 'cp-no-properties',
  PROPERTY_NOT_ALLOWED: 'cp-property-not-allowed',
  ADDRESS_ICON_DISABLED: 'cp-address-icon-disabled',
  MULTIPLE_DISABLED: 'cp-multiple-disabled',
  TOO_MANY_CONTACTS: 'cp-too-many-contacts',
  RATE_LIMIT: 'cp-rate-limit',
});

const CP_SUPPORTED = Object.freeze(['name', 'email', 'tel', 'address', 'icon']);

function defaultContactPickerPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    requireVisible: true,
    allowedProperties: ['name', 'email', 'tel'],
    allowAddress: false,
    allowIcon: false,
    allowMultiple: false,
    maxContacts: 1,
    maxPicksPerMinute: 3,
  };
}

class ContactPickerGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultContactPickerPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.pickTimes = [];
  }

  // decideSelect 裁决 contacts.select(properties, options)。
  decideSelect(ctx, properties, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: CP_DENY, reason: CP_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: CP_DENY, reason: CP_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: CP_DENY, reason: CP_REASON.NO_GESTURE };
    if (pol.requireVisible && ctx.visible === false) return { decision: CP_DENY, reason: CP_REASON.NOT_VISIBLE };

    if (!Array.isArray(properties) || properties.length === 0) return { decision: CP_DENY, reason: CP_REASON.NO_PROPERTIES };
    for (const prop of properties) {
      if (CP_SUPPORTED.indexOf(prop) < 0) return { decision: CP_DENY, reason: CP_REASON.PROPERTY_NOT_ALLOWED, property: prop };
      if (prop === 'address' && !pol.allowAddress) return { decision: CP_DENY, reason: CP_REASON.ADDRESS_ICON_DISABLED, property: 'address' };
      if (prop === 'icon' && !pol.allowIcon) return { decision: CP_DENY, reason: CP_REASON.ADDRESS_ICON_DISABLED, property: 'icon' };
      if (pol.allowedProperties.indexOf(prop) < 0) return { decision: CP_DENY, reason: CP_REASON.PROPERTY_NOT_ALLOWED, property: prop };
    }

    const opt = options && typeof options === 'object' ? options : {};
    if (opt.multiple === true && !pol.allowMultiple) return { decision: CP_DENY, reason: CP_REASON.MULTIPLE_DISABLED };

    const now = this.clock();
    this.pickTimes = this.pickTimes.filter((t) => now - t < 60000);
    if (this.pickTimes.length >= pol.maxPicksPerMinute) return { decision: CP_DENY, reason: CP_REASON.RATE_LIMIT };
    this.pickTimes.push(now);
    return { decision: CP_ALLOW, reason: '', maxContacts: pol.maxContacts };
  }

  // decideResult 对选择器返回的联系人条数做复核。
  decideResult(contacts) {
    const pol = this.policy;
    if (!Array.isArray(contacts)) return { decision: CP_DENY, reason: CP_REASON.TOO_MANY_CONTACTS };
    if (contacts.length > pol.maxContacts) return { decision: CP_DENY, reason: CP_REASON.TOO_MANY_CONTACTS, count: contacts.length };
    return { decision: CP_ALLOW, reason: '' };
  }
}

module.exports = {
  CP_ALLOW, CP_DENY, CP_REASON, CP_SUPPORTED,
  defaultContactPickerPolicy, ContactPickerGuard,
};
