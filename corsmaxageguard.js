'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'CORSMAXAG', label: 'CORS Access-Control-Max-Age' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCorsmaxageGuard: guard.evaluate,
  describeCorsmaxageGuard: guard.describe,
};
