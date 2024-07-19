import dbPool from '../config/database.js';
import bcrypt from 'bcrypt';

const getConnection = async () => {
  return await dbPool.getConnection();
};

const getAllUser = async () => {
  return dbPool.query('SELECT * from users');
};

const createUser = async (
  connection,
  username,
  email,
  password,
  is_email_verified,
  sign_up_source,
  sign_up_timestamps,
  token
) => {
  await connection.query(
    'INSERT INTO users (username, email, password, is_email_verified, sign_up_source, sign_up_timestamps, verification_token) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [
      username,
      email,
      password,
      is_email_verified,
      sign_up_source,
      sign_up_timestamps,
      token,
    ]
  );
};

const checkEmailExist = async (email) => {
  const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ?', [
    email,
  ]);

  return rows.length > 0;
};

const findUserByToken = async (token) => {
  const connection = await dbPool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT * FROM users WHERE verification_token = ?',
      [token]
    );

    return rows[0];
  } catch (error) {
    throw error;
  } finally {
    connection.release();
  }
};

const updateUserByToken = async (token, updates) => {
  const { is_email_verified, verification_token } = updates;

  await dbPool.query(
    'UPDATE users SET is_email_verified = ?, verification_token =? WHERE verification_token = ?',
    [is_email_verified, verification_token, token]
  );
};

const findByEmail = async (email) => {
  try {
    const connection = await dbPool.getConnection();

    const [results] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    connection.release();

    return results[0];
  } catch (err) {
    console.error('Error in findByEmail:', err);
    throw err;
  }
};

const comparePassword = async (password, hash) => {
  try {
    let isMatch = await bcrypt.compare(password, hash);

    return isMatch;
  } catch (error) {
    console.error('Error in comparePassword:', err);
    throw err;
  }
};

const findById = async (id) => {
  let connection;
  try {
    connection = await dbPool.getConnection();

    const [results] = await connection.query(
      'SELECT * FROM users WHERE id = ?',
      [id]
    );

    return results[0];
  } catch (err) {
    console.error('Error in findById:', err);
    throw err;
  } finally {
    if (connection) connection.release();
  }
};

export default {
  getConnection,
  createUser,
  checkEmailExist,
  findUserByToken,
  updateUserByToken,
  getAllUser,
  findByEmail,
  comparePassword,
  findById,
};
