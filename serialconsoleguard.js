'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'serialconsole', prefix: 'SERIALCON' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSerialconsoleGuard: guard.evaluate,
  summarizeSerialconsoleGuard: guard.summarize,
  describeSerialconsoleGuard: guard.describe,
};
