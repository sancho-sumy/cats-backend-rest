import { Request, Response, NextFunction } from 'express';
import { get } from 'lodash';
import { reIssueAccessToken } from '../services/session.service';
import { verifyJwt } from '../utils/jwt.utils';

const deserializeUser = async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = get(req, 'headers.authorization', '').replace(/^Bearer\s/, '');

    const refreshToken = get(req, 'headers.x-refresh', '') as string;

    if (!accessToken) {
        return next();
    }

    const { decoded, expired } = verifyJwt(accessToken);

    if (decoded) {
        res.locals.user = decoded;

        return next();
    }

    if (expired && refreshToken) {
        const newAccesToken = await reIssueAccessToken({ refreshToken });

        if (newAccesToken) {
            res.setHeader('x-access-token', newAccesToken);
        }

        const result = verifyJwt(newAccesToken as string);

        res.locals.user = result.decoded;

        return next();
    }

    return next();
};

export default deserializeUser;
