'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'SCRIPTNON', label: '脚本 nonce' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateScriptnonce: guard.evaluate,
  summarizeScriptnonce: guard.summarize,
  describeScriptnonce: guard.describe,
};
