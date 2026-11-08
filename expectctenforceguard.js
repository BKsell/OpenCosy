'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'EXPECTCTE', label: 'Expect-CT enforcement' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateExpectctenforceGuard: guard.evaluate,
  describeExpectctenforceGuard: guard.describe,
};
