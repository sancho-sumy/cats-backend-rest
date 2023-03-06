import { CookieOptions, Request, Response, NextFunction } from 'express';
import config from 'config';
import jwt from 'jsonwebtoken';
import { createSession, findSessions, updateSession } from '../services/session.service';
import { findAndUpdateUser, getGoogleOauthTokens, getGoogleUser, validatePassword } from '../services/user.service';
import CustomError from '../utils/error.utils';
import { signJwt } from '../utils/jwt.utils';
import logger from '../utils/logger.utils';

const accessTokenCookieOptions: CookieOptions = {
    maxAge: 900000, // 15 mins
    httpOnly: true,
    domain: 'localhost',
    path: '/',
    sameSite: 'lax',
    secure: false,
};

const refreshTokenCookieOptions: CookieOptions = {
    ...accessTokenCookieOptions,
    maxAge: 3.154e10, // 1 year
};

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

        res.cookie('accessToken', accessToken, accessTokenCookieOptions);

        res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

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

export async function googleOauthHandler(req: Request, res: Response) {
    const code = req.query.code as string;

    try {
        const { id_token, access_token } = await getGoogleOauthTokens({ code });

        // console.log({ id_token, access_token });

        // const googleUser = jwt.decode(id_token);

        const googleUser = await getGoogleUser({ id_token, access_token });

        console.log(googleUser);

        if (!googleUser.verified_email) {
            return res.status(403).send('Google account is not verified');
        }

        const user = await findAndUpdateUser(
            {
                email: googleUser.email,
            },
            {
                email: googleUser.email,
                name: googleUser.name,
                picture: googleUser.picture,
            },
            {
                upsert: true,
                new: true,
            },
        );

        if (!user) {
            const error = new CustomError('Invalid user', { statusCode: 401 });
            throw error;
        }

        const session = await createSession(user._id, req.get('user-agent') || '');

        const accessToken = signJwt(
            { ...user.toJSON, session: session._id },
            { expiresIn: config.get<string>('security.accessTokenTtl') },
        );

        const refreshToken = signJwt(
            { ...user.toJSON, session: session._id },
            { expiresIn: config.get<string>('security.refreshTokenTtl') },
        );

        console.log({ accessToken });

        res.cookie('accessToken', accessToken, accessTokenCookieOptions);

        res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

        res.redirect(config.get('server.origin'));
    } catch (error) {
        logger.error(error, 'Failed to authirize Google user');
        return res.redirect(`${config.get('server.origin')}/oauth/error`);
    }
}
