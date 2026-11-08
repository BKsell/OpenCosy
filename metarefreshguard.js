'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'metarefresh', prefix: 'METAREFRE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMetarefreshGuard: guard.evaluate,
  summarizeMetarefreshGuard: guard.summarize,
  describeMetarefreshGuard: guard.describe,
};
