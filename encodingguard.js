'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'encoding', prefix: 'ENCODING' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEncodingGuard: guard.evaluate,
  summarizeEncodingGuard: guard.summarize,
  describeEncodingGuard: guard.describe,
};
