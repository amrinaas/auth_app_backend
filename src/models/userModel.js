import dbPool from '../config/database.js';

const getConnection = async () => {
  return await dbPool.getConnection();
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

export default {
  getConnection,
  createUser,
  checkEmailExist,
  findUserByToken,
  updateUserByToken,
};
