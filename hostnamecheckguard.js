'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'hostnamecheck', prefix: 'HOSTNAMEC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHostnamecheckGuard: guard.evaluate,
  summarizeHostnamecheckGuard: guard.summarize,
  describeHostnamecheckGuard: guard.describe,
};
