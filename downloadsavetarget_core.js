const { hasAlternateDataStream, isReservedDeviceName } = require('./savenamechecks_core');
'use strict';
const { MAX_SAVE_NAME_CHARS, MAX_SAVE_PATH_CHARS, REASON, auditSaveName, auditSaveTarget, describeSaveTargetReject } = require('./savetargetrules_core');
require('./reasontext');

const fs = require('fs');
const path = require('path');
require('./downloadname_core');







function auditSaveTargetReal(rootDir, targetPath, name, deps) {
  const base = auditSaveTarget(rootDir, targetPath, name);
  if (!base.ok) return base;
  const existsFn = deps && typeof deps.existsSync === 'function' ? deps.existsSync : fs.existsSync;
  const realpathFn = deps && typeof deps.realpathSync === 'function' ? deps.realpathSync : fs.realpathSync;
  let rootReal;
  try {
    rootReal = realpathFn(path.resolve(rootDir));
  } catch (e) {
    return { ok: false, reason: REASON.REALPATH_UNRESOLVED, path: '', name: base.name };
  }
  let probe = path.dirname(base.path);
  const tail = [];
  while (!existsFn(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) {
      return { ok: false, reason: REASON.REALPATH_UNRESOLVED, path: '', name: base.name };
    }
    tail.unshift(path.basename(probe));
    probe = parent;
  }
  let probeReal;
  try {
    probeReal = realpathFn(probe);
  } catch (e) {
    return { ok: false, reason: REASON.REALPATH_UNRESOLVED, path: '', name: base.name };
  }
  const realTarget = path.join(probeReal, ...tail, base.name);
  const relative = path.relative(rootReal, realTarget);
  if (relative.length === 0 || relative.startsWith('..') || path.isAbsolute(relative)) {
    return { ok: false, reason: REASON.OUTSIDE_ROOT, path: base.path, name: base.name };
  }
  return { ok: true, reason: REASON.OK, path: base.path, name: base.name };
}

module.exports = {
  REASON,
  MAX_SAVE_NAME_CHARS,
  MAX_SAVE_PATH_CHARS,
  auditSaveName,
  auditSaveTarget,
  auditSaveTargetReal,
  describeSaveTargetReject,
  hasAlternateDataStream,
  isReservedDeviceName,
};
