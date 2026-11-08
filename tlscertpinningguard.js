'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'TLSCERTPI', label: '证书固定' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTlscertpinning: guard.evaluate,
  summarizeTlscertpinning: guard.summarize,
  describeTlscertpinning: guard.describe,
};
