'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CSPREPORT', label: 'CSP report-to endpoint' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCspreporttoendpointGuard: guard.evaluate,
  describeCspreporttoendpointGuard: guard.describe,
};
