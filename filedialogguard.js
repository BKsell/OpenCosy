'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'filedialog', prefix: 'FILEDIALO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFiledialogGuard: guard.evaluate,
  summarizeFiledialogGuard: guard.summarize,
  describeFiledialogGuard: guard.describe,
};
