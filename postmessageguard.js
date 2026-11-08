'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'postmessage', prefix: 'POSTMESSA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePostmessageGuard: guard.evaluate,
  summarizePostmessageGuard: guard.summarize,
  describePostmessageGuard: guard.describe,
};
