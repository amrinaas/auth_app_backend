import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import userModel from '../models/userModel.js';
import { promisify } from 'util';
import { generateToken, sendRefreshToken } from '../utils/tokenUtils.js';
import jwt from 'jsonwebtoken';

const register = async (req, res) => {
  const connection = await userModel.getConnection();
  let shouldCommit = false;

  try {
    await connection.beginTransaction();

    const { username, email, password, reEnterPassword } = req.body;

    if (password !== reEnterPassword)
      return res.status(400).json({ message: "Password doesn't match" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const is_email_verified = false;
    const sign_up_source = 'Manual';
    const sign_up_timestamps = new Date();

    await userModel.createUser(
      connection,
      username,
      email,
      hashedPassword,
      is_email_verified,
      sign_up_source,
      sign_up_timestamps,
      token
    );

    await sendVerificationEmail(email, token);
    await connection.commit();
    shouldCommit = true;

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (!shouldCommit) {
      await connection.rollback();
    }
    console.error('Transaction failed, rolled back.', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    connection.release();
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
    throw new Error('Failed to send verification email');
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    const user = userModel.findUserByToken({ verification_token: token });

    if (!user) {
      res.status(404).json({ message: 'Invalid verification token.' });
    }

    await userModel.updateUserByToken(token, {
      is_email_verified: true,
      verification_token: null,
    });

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

const getAllUsers = async (req, res) => {
  try {
    const [user] = await userModel.getAllUser();
    res.status(201).json({
      data: user,
      message: 'Successfully get all user',
    });
  } catch (error) {
    console.error(error);
  }
};

const logout = (req, res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    path: '/user/refresh-token',
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.status(200).json({ message: 'Logout successful' });
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

export default {
  register,
  verifyEmail,
  getAllUsers,
  getUserById,
  login,
  refreshToken,
  logout,
  updateUserName,
  updatePassword,
};
