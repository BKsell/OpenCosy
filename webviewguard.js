'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'webview', prefix: 'WEBVIEW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWebviewGuard: guard.evaluate,
  summarizeWebviewGuard: guard.summarize,
  describeWebviewGuard: guard.describe,
};
