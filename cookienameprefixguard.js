'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'COOKIENAM', label: 'Cookie 名称前缀' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookienameprefix: guard.evaluate,
  summarizeCookienameprefix: guard.summarize,
  describeCookienameprefix: guard.describe,
};
