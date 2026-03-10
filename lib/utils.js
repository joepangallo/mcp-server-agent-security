const crypto = require("crypto");

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise.finally(() => {
      if (timer) {
        clearTimeout(timer);
      }
    }),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.ceil(timeoutMs / 1000)}s`)), timeoutMs);
      if (typeof timer.unref === "function") {
        timer.unref();
      }
    })
  ]);
}

async function importFirst(specifiers) {
  let lastError;

  for (const specifier of specifiers) {
    try {
      return await import(specifier);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError;
}

let uuidv4 = () => crypto.randomUUID();
try {
  uuidv4 = require("uuid").v4;
} catch (error) {
  uuidv4 = () => crypto.randomUUID();
}

module.exports = {
  isPlainObject,
  withTimeout,
  importFirst,
  uuidv4
};
