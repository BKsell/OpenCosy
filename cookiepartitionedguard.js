'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'COOKIEPAR', label: 'Cookie Partitioned attribute' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCookiepartitionedGuard: guard.evaluate,
  describeCookiepartitionedGuard: guard.describe,
};
