'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'arp', prefix: 'ARP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateArpGuard: guard.evaluate,
  summarizeArpGuard: guard.summarize,
  describeArpGuard: guard.describe,
};
