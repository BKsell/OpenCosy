'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webviewtag', prefix: 'WEBVIEWTA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebviewtagGuard: guard.evaluate,
  summarizeWebviewtagGuard: guard.summarize,
  describeWebviewtagGuard: guard.describe,
};
