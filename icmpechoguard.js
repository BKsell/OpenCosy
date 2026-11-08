'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'icmpecho', prefix: 'ICMPECHO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIcmpechoGuard: guard.evaluate,
  summarizeIcmpechoGuard: guard.summarize,
  describeIcmpechoGuard: guard.describe,
};
