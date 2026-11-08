'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fileacl', prefix: 'FILEACL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFileaclGuard: guard.evaluate,
  summarizeFileaclGuard: guard.summarize,
  describeFileaclGuard: guard.describe,
};
