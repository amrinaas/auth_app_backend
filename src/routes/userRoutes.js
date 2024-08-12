import express from 'express';
import { userValidationRules, validate } from '../middlewares/validator.js';
import {
  authenticate,
  checkAndUpdateSession,
} from '../middlewares/authMiddleware.js';
import userController from '../controllers/userController.js';

const router = express.Router();

router.post(
  '/register',
  userValidationRules(),
  validate,
  userController.register
);
router.get('/verify/:token', userController.verifyEmail);
router.get('/refresh-token', userController.refreshToken);
router.post('/login', userController.login);
router.delete('/logout/:id', userController.logout);
router.put('/', userController.updateUserName);
router.put('/:id/password', userController.updatePassword);
router.get(
  '/resend-email-verification/:id',
  userController.resendVerificationEmail
);
router.get('/details', authenticate, userController.getUserById);
router.get('/total-users', userController.getTotalUsers);
router.get('/users-dashboard', userController.getUsersDashboard);
router.get('/active-session', userController.countActiveSession);
router.get('/average-active-session', userController.countAverageSession);

router.get('/auth/facebook', userController.facebookAuth);
router.get(
  '/auth/facebook/callback',
  userController.facebookAuthCallback,
  userController.authSuccess
);
router.get('/auth/google', userController.googleAuth);
router.get(
  '/auth/google/callback',
  userController.googleAuthCallback,
  userController.authSuccess
);
router.get('/check-session', checkAndUpdateSession);

export default router;
