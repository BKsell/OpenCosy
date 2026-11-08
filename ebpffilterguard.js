'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ebpffilter', prefix: 'EBPFFILTE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEbpffilterGuard: guard.evaluate,
  summarizeEbpffilterGuard: guard.summarize,
  describeEbpffilterGuard: guard.describe,
};
