'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPREPORT', label: 'Content-Security-Policy-Report-Only' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspreportonlyenforceGuard: guard.evaluate,
  describeCspreportonlyenforceGuard: guard.describe,
};
