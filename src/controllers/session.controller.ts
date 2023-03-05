import { Request, Response, NextFunction } from 'express';
import { createSession, findSessions, updateSession } from '../services/session.service';
import { validatePassword } from '../services/user.service';
import CustomError from '../utils/error.utils';
import config from 'config';
import { signJwt } from '../utils/jwt.utils';

export async function createUserSessionHandler(req: Request, res: Response, next: NextFunction) {
    try {
        const user = await validatePassword(req.body);

        if (!user) {
            const error = new CustomError('Invalid email or password', { statusCode: 401 });
            throw error;
        }

        const session = await createSession(user._id, req.get('user-agent') || '');

        const accessToken = signJwt(
            { ...user, session: session._id },
            { expiresIn: config.get<string>('security.accessTokenTtl') },
        );

        const refreshToken = signJwt(
            { ...user, session: session._id },
            { expiresIn: config.get<string>('security.refreshTokenTtl') },
        );

        return res.send({ accessToken, refreshToken });
    } catch (error: any) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }
        next(error);
    }
}

export async function getUserSessionHandler(req: Request, res: Response) {
    const userId = res.locals.user._id;

    const sessions = await findSessions({ user: userId, valid: true });

    return res.send(sessions);
}

export async function deleteSessionHandler(req: Request, res: Response) {
    const sessionId = res.locals.user.session;

    await updateSession({ _id: sessionId }, { valid: false });

    return res.send({
        accessToken: null,
        refreshToken: null,
    });
}
