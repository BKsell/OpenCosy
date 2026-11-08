'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'COLORPROF', label: '色彩配置白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateColorprofileallowlist: guard.evaluate,
  summarizeColorprofileallowlist: guard.summarize,
  describeColorprofileallowlist: guard.describe,
};
