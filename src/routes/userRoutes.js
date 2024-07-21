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
router.get('/refresh-token', userController.refreshToken);
router.post('/login', userController.login);
router.delete('/logout', userController.logout);
router.put('/', userController.updateUserName);
router.put('/:id/password', userController.updatePassword);
router.get('/details', authenticate, userController.getUserById);

// router.get('/', userController.getUsersDashboard);

// router.get('/total-users', userController.getTotalUsers);
// router.get('/active-sessions-today', userController.getActiveSessionsToday);
// router.get('/average-active-sessions', userController.getAverageActiveSessions);

// router.get('/auth/google', userController.googleAuth);
// router.get(
//   '/auth/google/callback',
//   userController.googleAuthCallback,
//   userController.authSuccess
// );

// router.get('/auth/facebook', userController.facebookAuth);
// router.get(
//   '/auth/facebook/callback',
//   userController.facebookAuthCallback,
//   userController.authSuccess
// );

export default router;
