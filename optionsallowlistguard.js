'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'OPTIONSAL', label: 'OPTIONS 方法白名单' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOptionsallowlist: guard.evaluate,
  summarizeOptionsallowlist: guard.summarize,
  describeOptionsallowlist: guard.describe,
};
