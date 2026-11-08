'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'ETAGWEAKF', label: '弱 ETag 禁用' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEtagweakforbid: guard.evaluate,
  summarizeEtagweakforbid: guard.summarize,
  describeEtagweakforbid: guard.describe,
};
