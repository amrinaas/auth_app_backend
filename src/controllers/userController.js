import bcrypt from 'bcrypt';
import userModel from '../models/userModel.js';

const register = async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      is_email_verified,
      sign_up_source,
      sign_up_timestamps,
    } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    await userModel.createUser(
      username,
      email,
      hashedPassword,
      is_email_verified,
      sign_up_source,
      sign_up_timestamps
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
};

export default { register };
