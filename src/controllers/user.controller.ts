import { Request, Response, NextFunction } from 'express';
import { createUser } from '../services/user.service';
import logger from '../utils/logger.utils';

export async function createUserHandler(req: Request, res: Response, next: NextFunction) {
    try {
        const user = await createUser(req.body);
        logger.info('New user created');
        return res.send(user);
    } catch (error: any) {
        logger.error(error);
        error.statusCode = 409;
        next(error);
    }
}

