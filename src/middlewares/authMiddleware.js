import { validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';

export const authenticate = (req, res, next) => {
  const header = req.header('Authorization');
  const token = header && header.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unathorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: error.message });
  }
};

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};
