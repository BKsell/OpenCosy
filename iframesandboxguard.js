'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'IFRAMESAN', label: 'iframe sandbox' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIframesandbox: guard.evaluate,
  summarizeIframesandbox: guard.summarize,
  describeIframesandbox: guard.describe,
};
