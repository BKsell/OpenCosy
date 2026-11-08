'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'otr', prefix: 'OTR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOtrGuard: guard.evaluate,
  summarizeOtrGuard: guard.summarize,
  describeOtrGuard: guard.describe,
};
