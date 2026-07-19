'use strict';

const Module = require('node:module');

/**
 * bdb imports its native LevelDB adapter eagerly even when hsd is configured
 * with `memory: true`. On platforms without a matching leveldown binary this
 * prevents an otherwise pure in-memory oracle from starting. Install a class
 * that can never be constructed only when that eager native import fails;
 * MemDB remains the backend selected by every oracle driver.
 */
function installMemoryOnlyDatabaseShim(hsdRoot) {
  const filename = require.resolve('bdb/lib/level', {paths: [hsdRoot]});
  try {
    require(filename);
    return false;
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND' || !/leveldown/.test(error.message))
      throw error;
  }
  class DisabledPersistentLevelDB {
    constructor() {
      throw new Error('persistent LevelDB is disabled in the memory-only hsd oracle');
    }
  }
  const stub = new Module(filename);
  stub.filename = filename;
  stub.loaded = true;
  stub.exports = DisabledPersistentLevelDB;
  require.cache[filename] = stub;
  return true;
}

module.exports = {installMemoryOnlyDatabaseShim};
