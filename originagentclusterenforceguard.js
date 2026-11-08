'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'ORIGINAGE', label: 'Origin-Agent-Cluster' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOriginagentclusterenforceGuard: guard.evaluate,
  describeOriginagentclusterenforceGuard: guard.describe,
};
