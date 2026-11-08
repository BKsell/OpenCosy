'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'privatekey', prefix: 'PRIVATEKE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePrivatekeyGuard: guard.evaluate,
  summarizePrivatekeyGuard: guard.summarize,
  describePrivatekeyGuard: guard.describe,
};
