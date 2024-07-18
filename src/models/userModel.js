import dbPool from '../config/database.js';

const createUser = async (
  username,
  email,
  password,
  is_email_verified,
  sign_up_source,
  sign_up_timestamps
) => {
  await dbPool.query(
    'INSERT INTO users (username, email, password, is_email_verified, sign_up_source, sign_up_timestamps) VALUES (?, ?, ?, ?, ?, ?)',
    [
      username,
      email,
      password,
      is_email_verified,
      sign_up_source,
      sign_up_timestamps,
    ]
  );
};

const checkEmailExist = async (email) => {
  const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ?', [
    email,
  ]);

  return rows.length > 0;
};

export default { createUser, checkEmailExist };
