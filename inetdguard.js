'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'inetd', prefix: 'INETD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateInetdGuard: guard.evaluate,
  summarizeInetdGuard: guard.summarize,
  describeInetdGuard: guard.describe,
};
