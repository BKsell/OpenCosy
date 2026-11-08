'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'clipboardformat', prefix: 'CLIPBOARD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateClipboardformatGuard: guard.evaluate,
  summarizeClipboardformatGuard: guard.summarize,
  describeClipboardformatGuard: guard.describe,
};
