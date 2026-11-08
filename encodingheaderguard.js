'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'encodingheader', prefix: 'ENCODINGH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEncodingheaderGuard: guard.evaluate,
  summarizeEncodingheaderGuard: guard.summarize,
  describeEncodingheaderGuard: guard.describe,
};
