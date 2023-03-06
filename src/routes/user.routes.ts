import express from 'express';
import validate from '../middleware/validateResource';

import { createUserHandler, getCurrentUser } from '../controllers/user.controller';
import { createUserSchema } from '../schemas/user.schema';
import requireUser from '../middleware/requireUser';

const router = express.Router();

router.post('/', validate(createUserSchema), createUserHandler);

router.get('/me', requireUser, getCurrentUser);

export default router;
