'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'ALTSVCALL', label: 'Alt-Svc 白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAltsvcallowlist: guard.evaluate,
  summarizeAltsvcallowlist: guard.summarize,
  describeAltsvcallowlist: guard.describe,
};
