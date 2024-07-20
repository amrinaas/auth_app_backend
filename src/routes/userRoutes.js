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
router.get('/', userController.getAllUsers);
router.get('/verify/:token', userController.verifyEmail);
router.get('/refresh-token', userController.refreshToken);
router.post('/login', userController.login);
router.delete('/logout', userController.logout);
router.put('/', userController.updateUserName);
router.get('/details', authenticate, userController.getUserById);

export default router;
