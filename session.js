import { gzipSync } from 'zlib';
import { createHash } from 'crypto';

export const encodeSession = (credsBuffer) => {
    const compressed = gzipSync(credsBuffer);
    return `sage~${compressed.toString('base64')}`;
};

export const randomId = (prefixLen = 6) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let prefix = '';
    for (let i = 0; i < prefixLen; i++) {
        prefix += chars[Math.floor(Math.random() * chars.length)];
    }
    const tsBase36 = Date.now().toString(36);
    const hexSuffix = createHash('sha256')
        .update(String(Math.random()))
        .digest('hex')
        .slice(0, 4);
    return `${prefix}-${tsBase36}-${hexSuffix}`;
};
