import express from 'express';
import { userValidationRules } from '../middlewares/validator.js';
import { validate } from '../middlewares/authMiddleware.js';
import userController from '../controllers/userController.js';

const router = express.Router();

router.post(
  '/register',
  userValidationRules(),
  validate,
  userController.register
);
router.get('/verify/:token', userController.verifyEmail);

export default router;
