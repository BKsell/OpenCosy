'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'VARYORIGI', label: 'Vary Origin 必须' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateVaryoriginrequire: guard.evaluate,
  summarizeVaryoriginrequire: guard.summarize,
  describeVaryoriginrequire: guard.describe,
};
