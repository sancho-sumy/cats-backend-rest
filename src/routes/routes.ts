import { Express, Request, Response } from 'express';
import { createUserSessionHandler } from '../controllers/session.controller';
import { createUserHandler } from '../controllers/user.controller';
import validate from '../middleware/validateResource';
import { createSessionSchema } from '../schemas/session.schema';
import { createUserSchema } from '../schemas/user.schema';

function routes(app: Express) {
    app.get('/healthcheck', (req: Request, res: Response) => {
        res.sendStatus(200);
    });

    app.post('/api/users', validate(createUserSchema), createUserHandler);
    app.post('/api/sessions', validate(createSessionSchema), createUserSessionHandler);
}

export default routes;
