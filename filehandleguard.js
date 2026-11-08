'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'filehandle', prefix: 'FILEHANDL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFilehandleGuard: guard.evaluate,
  summarizeFilehandleGuard: guard.summarize,
  describeFilehandleGuard: guard.describe,
};
