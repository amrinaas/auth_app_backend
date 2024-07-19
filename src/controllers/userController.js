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

    const { username, email, password, sign_up_source, sign_up_timestamps } =
      req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString('hex');
    const is_email_verified = false;

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

    res
      .status(200)
      .json({ message: 'Email verified successfully. You can log in now.' });
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
  const { id } = req.params;

  try {
    const user = await userModel.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({
      message: 'Success get user',
      data: { id: user.id, email: user.email, username: user.username },
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

export default {
  register,
  verifyEmail,
  getAllUsers,
  getUserById,
  login,
  refreshToken,
};
