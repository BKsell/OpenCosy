'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'upgradeheader', prefix: 'UPGRADEHE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateUpgradeheaderGuard: guard.evaluate,
  summarizeUpgradeheaderGuard: guard.summarize,
  describeUpgradeheaderGuard: guard.describe,
};
