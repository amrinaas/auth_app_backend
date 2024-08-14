import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import userModel from '../models/userModel.js';
import { promisify } from 'util';
import {
  generateToken,
  sendTokens,
  sendRefreshToken,
  clearTokens,
} from '../utils/tokenUtils.js';
import jwt from 'jsonwebtoken';
import passport from 'passport';

const register = async (req, res) => {
  try {
    const { username, email, password, reEnterPassword } = req.body;

    if (password !== reEnterPassword)
      return res.status(400).json({ message: "Password doesn't match" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const verified = false;
    const isOAuth = false;
    const createdAt = new Date();

    await userModel.createUser(
      username,
      email,
      hashedPassword,
      token,
      verified,
      createdAt,
      isOAuth
    );

    await sendVerificationEmail(email, token);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

const transporter = nodemailer.createTransport({
  host: process.env.NODEMAILER_HOST,
  port: 465,
  secure: true,
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD,
  },
});

const sendMail = promisify(transporter.sendMail).bind(transporter);

const sendVerificationEmail = async (email, token) => {
  const output = `
    <h1>Hello,<br>Click the link below to verify your email.</h1>
    <button><a href="${process.env.EMAIL_HOST}/user/verify/${token}">${process.env.EMAIL_HOST}/user/verify/${token}</a></button>
  `;
  const mailOptions = {
    from: '"Nodemailer contact" <admin@infiniteinvites.com>',
    to: email,
    subject: 'Please verify your email',
    text: `Click the link to verify your account:`,
    html: output,
  };

  try {
    await sendMail(mailOptions);
    console.log('Email has been sent to: ', email);
    return 'Verification email sent!';
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
};

const resendVerificationEmail = async (req, res) => {
  const { id } = req.params;

  try {
    const token = crypto.randomBytes(32).toString('hex');
    const user = await userModel.findById(id);

    if (!user) return res.status(400).json({ message: 'User not found' });

    const output = `
    <h1>Hello,<br>Click the link below to verify your email.</h1>
    <button><a href="${process.env.EMAIL_HOST}/user/verify/${token}">${process.env.EMAIL_HOST}/user/verify/${token}</a></button>
  `;

    const mailOptions = {
      from: '"Nodemailer contact" <admin@infiniteinvites.com>',
      to: user.email,
      subject: 'Please verify your email',
      text: `Click the link to verify your account:`,
      html: output,
    };
    await userModel.updateToken({ email: user.email, token: token });
    await sendMail(mailOptions);
    clearTokens(res);
    res.status(200).json({ message: 'Resend email successful' });

    console.log('Resend Email has been sent to: ', user.email);
    return 'Verification email sent!';
  } catch (error) {
    console.error('Error sending resend email:', error);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.params;
  try {
    const user = await userModel.findUserByToken(token);

    if (!user) {
      res.redirect('http://localhost:3000/invalid-token');
      return;
    }

    await userModel.updateUserByToken({ verified: true, token: token });

    res.redirect('http://localhost:3000/');
  } catch (error) {
    console.error('error', error);
    res.status(500).json({ message: 'Error verifying email.' });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userModel.findByEmail(email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isMatch = await userModel.comparePassword(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credential' });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateToken(user);

    // Send both access and refresh token as a cookie
    sendTokens(res, accessToken, refreshToken);

    // Storing user activities
    logUserActivity(user.id, 'login');

    // Set session end is null
    userModel.updateSessionLogin({ userId: user.id });
    res.status(200).json({ accessToken, message: 'Login successful' });
  } catch (error) {
    console.error('Error in login:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) {
    return res.status(403).json({ message: 'Refresh token not provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateToken(user);
    sendRefreshToken(res, newRefreshToken);

    res.status(200).json({ accessToken });
  } catch (error) {
    console.error('Error in refreshToken:', error);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};

const getUserById = async (req, res) => {
  try {
    const user = await userModel.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({
      message: 'Success get user',
      data: {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: user.verified,
        isOAuth: user.isOAuth,
      },
    });
  } catch (error) {
    console.error('Error in getUserById:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const logout = async (req, res) => {
  const { id } = req.params;

  try {
    await userModel.logoutUser(id);
    clearTokens(res);

    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('error logout', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const logUserActivity = async (id, action) => {
  await userModel.createUserActivity({
    userId: id,
    action: action,
    timestamps: new Date(),
  });
};

const updateUserName = async (req, res) => {
  const { username, id } = req.body;

  if (!username || !id) {
    return res.status(400).json({ message: 'ID and username is required' });
  }

  try {
    await userModel.updateUserName(username, id);
    res.status(200).json({ message: 'Update name successful' });
  } catch (error) {
    console.error('Error update username', error);
  }
};

const updatePassword = async (req, res) => {
  const { id } = req.params;
  const { oldPassword, newPassword, reEnterNewPassword } = req.body;
  console.log(req.body);
  console.log(reEnterNewPassword);

  if (newPassword !== reEnterNewPassword)
    return res.status(400).json({ message: "New password doesn't match" });

  try {
    const user = await userModel.findById(id);

    if (!user) return res.status(400).json({ message: 'User not found' });

    if (user.isOAuth) {
      await userModel.setPassword({
        id: id,
        newPassword: newPassword,
        isOAuth: false,
      });
    } else {
      const isMatch = await bcrypt.compare(oldPassword, user.password);

      if (!isMatch)
        return res.status(400).json({ message: 'Old password is incorrect' });

      await userModel.updatePassword(id, newPassword);
    }
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error update password', error);
    res.status(500).json({ error: error.message });
  }
};

const getTotalUsers = async (req, res) => {
  try {
    const totalUsers = await userModel.getTotalUsers();
    res
      .status(200)
      .json({ totalUsers: totalUsers, message: 'Get all users successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getUsersDashboard = async (req, res) => {
  try {
    const page = parseInt(req.query.page);
    const pageSize = parseInt(req.query.pageSize);

    const startIndex = (page - 1) * pageSize;
    const endIndex = page * pageSize;

    const users = await userModel.getUsersDashboard();
    const paginated = users.slice(startIndex, endIndex);

    const totalPages = Math.ceil(users.length / pageSize);

    res
      .status(200)
      .json({ data: paginated, totalPages, message: 'Success get all users' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const facebookAuth = passport.authenticate('facebook', { scope: ['email'] });

const facebookAuthCallback = passport.authenticate('facebook', {
  failureRedirect: `${process.env.WEBSITE}/login`,
  session: false,
});

const authSuccess = async (req, res) => {
  // Generate tokens
  const { accessToken, refreshToken } = generateToken(req.user);
  // Send refresh token as a cookie
  sendTokens(res, accessToken, refreshToken);

  const email = req.user.email ? req.user.email : req.user.emails[0].value;
  const user = await userModel.findByEmail(email);

  // Storing user activities
  logUserActivity(user.id, 'login');
  res.redirect(`${process.env.WEBSITE}/`);
};

const googleAuth = passport.authenticate('google', {
  scope: ['profile', 'email'],
});

const googleAuthCallback = passport.authenticate('google', {
  failureRedirect: '/login',
  session: false,
});

const checkAndUpdateSession = async (id, req, res, next) => {
  try {
    await userModel.checkAndUpdateSession(id, req, res, next);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const countActiveSession = async (req, res, next) => {
  try {
    const totalActiveSession = await userModel.countActiveSession();

    res.status(200).json({
      totalActiveSession: totalActiveSession,
      message: 'Get active session in a day successfully',
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const countAverageSession = async (req, res, next) => {
  try {
    const averageSession = await userModel.countAverageSession();

    res.status(200).json({
      averageSession: averageSession,
      message: 'Get average session successfully',
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export default {
  register,
  verifyEmail,
  getUserById,
  login,
  refreshToken,
  logout,
  updateUserName,
  updatePassword,
  resendVerificationEmail,
  getTotalUsers,
  getUsersDashboard,
  facebookAuth,
  facebookAuthCallback,
  authSuccess,
  googleAuth,
  googleAuthCallback,
  checkAndUpdateSession,
  countActiveSession,
  countAverageSession,
};
