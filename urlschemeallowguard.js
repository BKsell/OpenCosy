'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'urlschemeallow', prefix: 'URLSCHEME' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUrlschemeallowGuard: guard.evaluate,
  summarizeUrlschemeallowGuard: guard.summarize,
  describeUrlschemeallowGuard: guard.describe,
};
