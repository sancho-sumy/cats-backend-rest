import express from 'express';
import validate from '../middleware/validateResource';

import { createUserHandler } from '../controllers/user.controller';
import { createUserSchema } from '../schemas/user.schema';

const router = express.Router();

router.post('/', validate(createUserSchema), createUserHandler);

export default router;
