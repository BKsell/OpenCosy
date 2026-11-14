'use strict';

function clearStoredFile(fsSync, storePath, label) {
  try {
    if (fsSync.existsSync(storePath)) fsSync.unlinkSync(storePath);
  } catch (e) {
    console.error(label, e);
  }
}

module.exports = { clearStoredFile };
