'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'XFRAMEOPT', label: 'X-Frame-Options 拒绝' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXframeoptionsdeny: guard.evaluate,
  summarizeXframeoptionsdeny: guard.summarize,
  describeXframeoptionsdeny: guard.describe,
};
