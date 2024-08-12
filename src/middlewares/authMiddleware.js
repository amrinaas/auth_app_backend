import jwt from 'jsonwebtoken';
import userController from '../controllers/userController.js';

export const authenticate = (req, res, next) => {
  const header = req.header('Authorization');
  const token = header && header.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unathorized' });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.error('Error Authenticate', error);
    res.status(401).json({ error: error.message });
  }
};

export const checkAndUpdateSession = (req, res, next) => {
  const token = req.cookies.accessToken;

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    userController.checkAndUpdateSession(decoded.id, req, res, next);
    res.status(200).json({ message: "Check user's session successfully" });
  } catch (error) {
    console.error('Error checkAndUpdateSession', error);
    res.status(401).json({ error: error.message });
  }
};
