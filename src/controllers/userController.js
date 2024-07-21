import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import userModel from '../models/userModel.js';
import { promisify } from 'util';
import { generateToken, sendRefreshToken } from '../utils/tokenUtils.js';
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
    const createdAt = new Date();

    await userModel.createUser(
      username,
      email,
      hashedPassword,
      token,
      verified,
      createdAt
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

const verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    const user = userModel.findUserByToken({ token: token });

    if (!user) {
      res.status(404).json({ message: 'Invalid verification token.' });
    }

    await userModel.updateUserByToken({ verified: true, token: token });

    res.redirect('http://localhost:3000/dashboard');
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

    // Send refresh token as a cookie
    sendRefreshToken(res, refreshToken);

    // Storing user activities
    await userModel.createUserActivity({
      userId: user.id,
      action: 'login',
      timestamps: new Date(),
    });

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
        is_email_verified: user.is_email_verified,
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
    const user = await userModel.findById(id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await userModel.createUserActivity({
      userId: id,
      action: 'logout',
      timestamps: new Date(),
    });

    res.clearCookie('refreshToken', {
      httpOnly: true,
      path: '/',
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'None',
    });

    res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.log('error logout', error);
    res.status(500).json({ error: 'Internal server error' });
  }
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

  if (newPassword !== reEnterNewPassword)
    return res.status(400).json({ message: "New password doesn't match" });

  try {
    const user = await userModel.findById(id);

    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch)
      return res.status(400).json({ message: 'Old password is incorrect' });

    await userModel.updatePassword(id, newPassword);
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error update password', error);
  }
};

// const googleAuth = passport.authenticate('google', {
//   scope: ['profile', 'email'],
// });

// const googleAuthCallback = passport.authenticate('google', {
//   failureRedirect: '/login',
//   session: false,
// });

// const facebookAuth = passport.authenticate('facebook', { scope: ['email'] });

// const facebookAuthCallback = passport.authenticate('facebook', {
//   failureRedirect: `${process.env.WEBSITE}/login`,
//   session: false,
// });

// const authSuccess = (req, res) => {
//   res.redirect(`${process.env.WEBSITE}/dashboard`);
// };

// const getTotalUsers = async (req, res) => {
//   try {
//     const totalUsers = await userModel.getTotalUsers();
//     res.json({ totalUsers });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// const getActiveSessionsToday = async (req, res) => {
//   try {
//     const activeSessionsToday = await userModel.getActiveSessionsToday();
//     res.json({ activeSessionsToday });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// const getAverageActiveSessions = async (req, res) => {
//   try {
//     const averageActiveSessions = await userModel.getAverageActiveSessions();
//     res.json({ averageActiveSessions });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// export const getUsersDashboard = async (req, res) => {
//   try {
//     const users = await userModel.getAllUsers();
//     res.status(200).json({ data: users, message: 'Success get all users' });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

export default {
  register,
  verifyEmail,
  getUserById,
  login,
  refreshToken,
  logout,
  updateUserName,
  updatePassword,
  // googleAuth,
  // googleAuthCallback,
  // facebookAuth,
  // facebookAuthCallback,
  // authSuccess,
  // getTotalUsers,
  // getActiveSessionsToday,
  // getAverageActiveSessions,
  // getUsersDashboard,
};
