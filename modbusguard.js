'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'modbus', prefix: 'MODBUS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateModbusGuard: guard.evaluate,
  summarizeModbusGuard: guard.summarize,
  describeModbusGuard: guard.describe,
};
