'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'avhook', prefix: 'AVHOOK' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAvhookGuard: guard.evaluate,
  summarizeAvhookGuard: guard.summarize,
  describeAvhookGuard: guard.describe,
};
