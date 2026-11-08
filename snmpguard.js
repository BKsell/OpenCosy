'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'snmp', prefix: 'SNMP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSnmpGuard: guard.evaluate,
  summarizeSnmpGuard: guard.summarize,
  describeSnmpGuard: guard.describe,
};
