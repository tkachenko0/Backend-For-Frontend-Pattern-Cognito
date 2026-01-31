import { createProxyMiddleware } from 'http-proxy-middleware';

export function createApiProxy(target: string, customClaims: string[]) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite: (path) => {
      return path.replace(/^\/api/, '');
    },
    onProxyReq: (proxyReq, req) => {
      const user = req.user;
      if (user) {
        proxyReq.setHeader('X-User-Sub', user['sub'] || '');
        proxyReq.setHeader('X-User-Email', user['email'] || '');

        customClaims.forEach((claim) => {
          if (user[claim] !== undefined) {
            const value = Array.isArray(user[claim])
              ? user[claim].join(',')
              : String(user[claim]);
            proxyReq.setHeader(`X-User-${claim.replace(/:/g, '-')}`, value);
          }
        });
      }
    },
    onError: (_err, _req, res) => {
      if (typeof res.status === 'function') {
        res.status(502).send({ error: 'Backend service unavailable' });
      }
    },
  });
}
