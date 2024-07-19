import express from 'express';
import { userValidationRules } from '../middlewares/validator.js';
import { validate, authenticate } from '../middlewares/authMiddleware.js';
import userController from '../controllers/userController.js';

const router = express.Router();

router.post(
  '/register',
  userValidationRules(),
  validate,
  userController.register
);
router.get('/verify/:token', userController.verifyEmail);
router.get('/get-users', userController.getAllUsers);
router.post('/login', userController.login);
router.get('/refresh-token', userController.refreshToken);
router.delete('/logout', userController.logout);
router.get('/:id', authenticate, userController.getUserById);

export default router;
