"use strict";

function getSafeDirs() {
  return [
    d.app.getPath('downloads'), d.app.getPath('documents'),
    d.app.getPath('desktop'), d.app.getPath('pictures'),
    d.app.getPath('videos'), d.app.getPath('music'), __dirname,
  ];
}
function isInSafeDirs(filePath) {
  return getSafeDirs().some(dir => isPathInDir(filePath, dir));
}
function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return d.ALLOWED_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}
function sanitizePath(inputPath, baseDir) {
  const resolved = d.path.resolve(baseDir, inputPath);
  const normalized = d.path.normalize(resolved);
  if (!isPathInDir(normalized, baseDir)) return null;
  return normalized;
}
function isPathInDir(filePath, dir) {
  return d.pathContain.isContained(dir, filePath, { realpath: realpathForContainment }).ok;
}
function realpathForContainment(p) {
  try {
    return d.fsSync.realpathSync.native(p);
  } catch {
    return null;
  }
}

module.exports = { getSafeDirs, isInSafeDirs, isSafeUrl, sanitizePath, isPathInDir, realpathForContainment };
