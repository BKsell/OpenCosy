'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'XDOWNLOAD', label: 'X-Download-Options' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXdownloadoptionsenforceGuard: guard.evaluate,
  describeXdownloadoptionsenforceGuard: guard.describe,
};
