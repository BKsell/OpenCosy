'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'serialport', prefix: 'SERIALPOR' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSerialportGuard: guard.evaluate,
  summarizeSerialportGuard: guard.summarize,
  describeSerialportGuard: guard.describe,
};
