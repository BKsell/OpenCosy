'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'HSTSMAXAG', label: 'HSTS max-age upper bound' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHstsmaxageupperboundGuard: guard.evaluate,
  describeHstsmaxageupperboundGuard: guard.describe,
};
