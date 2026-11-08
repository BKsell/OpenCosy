'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'originpull', prefix: 'ORIGINPUL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOriginpullGuard: guard.evaluate,
  summarizeOriginpullGuard: guard.summarize,
  describeOriginpullGuard: guard.describe,
};
