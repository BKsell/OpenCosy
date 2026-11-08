'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'dockerfile', prefix: 'DOCKERFIL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDockerfileGuard: guard.evaluate,
  summarizeDockerfileGuard: guard.summarize,
  describeDockerfileGuard: guard.describe,
};
