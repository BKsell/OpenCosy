'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'passwordmanager', prefix: 'PASSWORDM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePasswordmanagerGuard: guard.evaluate,
  summarizePasswordmanagerGuard: guard.summarize,
  describePasswordmanagerGuard: guard.describe,
};
