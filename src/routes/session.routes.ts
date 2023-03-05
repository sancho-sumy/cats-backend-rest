import express from 'express';
import validate from '../middleware/validateResource';

import {
    createUserSessionHandler,
    deleteSessionHandler,
    getUserSessionHandler,
} from '../controllers/session.controller';
import { createSessionSchema } from '../schemas/session.schema';
import requireUser from '../middleware/requireUser';

const router = express.Router();

router.post('/', validate(createSessionSchema), createUserSessionHandler);

router.get('/', requireUser, getUserSessionHandler);

router.delete('/', requireUser, deleteSessionHandler);

export default router;
