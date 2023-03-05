import jwt from 'jsonwebtoken';
import config from 'config'

const privateKey = config.get<string>('security.privateKey');
const publicKey = config.get<string>('security.publicKey');

export function signJwt(object: Object, options?: jwt.SignOptions | undefined) {
    return jwt.sign(object, privateKey, {
        ...(options && options),
        algorithm: 'RS256',
    });
}

export function verifyJwt(token: string) {
    try {
        const decoded = jwt.verify(token, publicKey);
        console.log('jwt:', decoded);
        
        return {
            valid: true,
            expired: false,
            decoded,
        };
    } catch (error: any) {
        return {
            valid: false,
            expired: error.message === 'jwt expired',
            decoded: null,
        };
    }
}
