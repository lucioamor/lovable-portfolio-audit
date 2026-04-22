/**
 * Recursively strip sensitive keys from an object before logging.
 */
function stripSensitive(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(stripSensitive);

  const safeObj = {};
  const blockedKeys = ['token', 'cookie', 'secret', 'password', 'authorization', 'evidence', 'raw'];

  for (const [key, value] of Object.entries(obj)) {
    if (blockedKeys.some(b => key.toLowerCase().includes(b))) {
      safeObj[key] = '[REDACTED]';
    } else {
      safeObj[key] = stripSensitive(value);
    }
  }
  return safeObj;
}

export const log = {
  info: (msg, ctx = {}) => {
    console.log(JSON.stringify({ ts: new Date().toISOString(), level: 'INFO', msg, ctx: stripSensitive(ctx) }));
  },
  error: (msg, err, ctx = {}) => {
    const errObj = err instanceof Error ? { message: err.message, stack: err.stack } : err;
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'ERROR', msg, error: errObj, ctx: stripSensitive(ctx) }));
  }
};
