import express, { Request, Response, NextFunction } from 'express';
import config from 'config';
import cors from "cors";
import cookieParser from "cookie-parser";
import connect from './utils/connect.utils';
import logger from './utils/logger.utils';

import deserializeUser from './middleware/deserializeUser';

import userRoutes from './routes/user.routes';
import sessionRoutes from './routes/session.routes';

interface Error {
    statusCode: number;
    message: string;
    data: any;
}

const port = config.get<number>('server.port');

const app = express();

app.use(
    cors({
        origin: config.get('server.origin'),
        credentials: true,
    }),
);

app.use(cookieParser());

app.use(express.json());

app.use(deserializeUser);

app.listen(port, async () => {
    logger.info(`App listening on http://localhost:${port}`);

    await connect();

    app.use((req: Request, res: Response, next: NextFunction) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        next();
    });

    app.use('/api/users', userRoutes);
    app.use('/api/sessions', sessionRoutes);

    app.get('/healthcheck', (req: Request, res: Response) => {
        res.sendStatus(200);
    });

    app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
        const status = error.statusCode || 500;
        const message = error.message;
        const data = error.data;
        res.status(status).json({ message: message, data: data });
    });
});
