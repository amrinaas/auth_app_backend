import { check } from 'express-validator';
import userModel from '../models/userModel.js';

export const userValidationRules = () => {
  return [
    check('username').notEmpty().withMessage('Username is required!'),
    check('email')
      .isEmail()
      .withMessage('Enter a valid email')
      .custom(async (email) => {
        const emailExist = await userModel.checkEmailExist(email);

        if (emailExist) {
          throw new Error('Email already in use');
        }
      }),
    check('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase')
      .matches(/[0-9]/)
      .withMessage('Password must contain at least one digit')
      .matches(/[^a-zA-Z0-9_]/)
      .withMessage('Password must contain at least one special character'),
  ];
};

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};
