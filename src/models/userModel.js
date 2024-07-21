import dbPool from '../config/database.js';
import bcrypt from 'bcrypt';

const connection = await dbPool.getConnection();

const createUser = async (
  username,
  email,
  password,
  token,
  verified,
  createdAt
) => {
  let shouldCommit = false;
  try {
    await connection.query(
      'INSERT INTO users (username, email, password, token, verified, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, password, token, verified, createdAt]
    );

    await connection.commit();
    shouldCommit = true;
    console.log('shouldCommit', shouldCommit);
  } catch (error) {
    if (!shouldCommit) {
      await connection.rollback();
    }
    console.error('Transaction failed, rolled back.', error);
    throw new Error(error);
  } finally {
    connection.release();
  }
};

const checkEmailExist = async (email) => {
  const [rows] = await dbPool.query('SELECT * FROM users WHERE email = ?', [
    email,
  ]);

  return rows.length > 0;
};

const findUserByToken = async (token) => {
  try {
    const [rows] = await connection.query(
      'SELECT * FROM users WHERE token = ?',
      [token]
    );

    return rows[0];
  } catch (error) {
    console.error('Error at findUserByToken', error);
    throw new Error(error);
  } finally {
    connection.release();
  }
};

const updateUserByToken = async (updates) => {
  const { verified, token } = updates;

  await dbPool.query(
    'UPDATE users SET verified = ?, token = ? WHERE token = ?',
    [verified, null, token]
  );
};

const updateToken = async (updates) => {
  const { email, token } = updates;

  await dbPool.query('UPDATE users SET token = ? WHERE email = ?', [
    token,
    email,
  ]);
};

const findByEmail = async (email) => {
  try {
    const [results] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    connection.release();

    return results[0];
  } catch (err) {
    console.error('Error in findByEmail:', err);
    throw new Error(err);
  }
};

const comparePassword = async (password, hash) => {
  try {
    let isMatch = await bcrypt.compare(password, hash);

    return isMatch;
  } catch (error) {
    console.error('Error in comparePassword:', err);
    throw new Error(err);
  }
};

const findById = async (id) => {
  try {
    const [results] = await connection.query(
      'SELECT * FROM users WHERE id = ?',
      [id]
    );

    return results[0];
  } catch (err) {
    console.error('Error in findById:', err);
    throw new Error(err);
  } finally {
    connection.release();
  }
};

const updateUserName = async (name, id) => {
  try {
    await connection.query('UPDATE users SET username = ? WHERE id = ?', [
      name,
      id,
    ]);
  } catch (err) {
    console.error('Error in findById:', err);
    throw new Error(err);
  } finally {
    connection.release();
  }
};

const updatePassword = async (id, newPassword) => {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  try {
    await connection.query('UPDATE users SET password = ? WHERE id = ?', [
      hashedPassword,
      id,
    ]);
  } catch (err) {
    console.error('Error in update password:', err);
    throw new Error(err);
  } finally {
    connection.release();
  }
};

const createUserActivity = async ({ userId, action, timestamps }) => {
  try {
    await connection.query(
      'INSERT INTO user_activities (userId, action, timestamps) VALUES (?, ?, ?)',
      [userId, action, timestamps]
    );
  } catch (error) {
    console.log('Error at createUserActivity', error);
    throw new Error(error);
  } finally {
    connection.release();
  }
};

// const findOrCreateUser = async (profile) => {
//   try {
//     console.log('profile', profile);
//     const [rows] = await connection.query(
//       'SELECT * FROM users WHERE oauth_id = ? AND sign_up_source = ?',
//       [profile.id, profile.provider]
//     );
//     if (rows.length > 0) {
//       return rows[0];
//     } else {
//       await pool.query(
//         'INSERT INTO users (oauth_id, sign_up_source, username, email, sign_up_timestamps, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)',
//         [
//           profile.id,
//           profile.provider,
//           profile.displayName,
//           profile.emails[0].value,
//           profile.sign_up_timestamps,
//           profile.is_email_verified,
//         ]
//       );
//       return { ...profile };
//     }
//   } catch (err) {
//     console.error('Error in update password:', err);
//     throw err;
//   } finally {
//     if (connection) connection.release();
//   }
// };

// const getTotalUsers = async () => {
//   const [rows] = await pool.query('SELECT COUNT(*) AS totalUsers FROM users');
//   return rows[0].totalUsers;
// };

// const getActiveSessionsToday = async () => {
//   const [rows] = await connection.query(`
//     SELECT COUNT(DISTINCT id) AS activeSessionsToday
//     FROM sessions
//     WHERE DATE(last_activity) = CURDATE()
//   `);
//   return rows[0].activeSessionsToday;
// };

// const getAverageActiveSessions = async () => {
//   const [rows] = await pool.query(`
//     SELECT AVG(dailyActiveUsers) AS averageActiveSessions
//     FROM (
//       SELECT COUNT(DISTINCT user_id) AS dailyActiveUsers
//       FROM sessions
//       WHERE last_activity >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
//       GROUP BY DATE(last_activity)
//     ) AS dailyStats
//   `);
//   return rows[0].averageActiveSessions;
// };

// const getAllUsers = async () => {
//   try {
//     const [rows] = await dbPool.query(`
//       SELECT
//         id,
//         username,
//         email,
//         sign_up_timestamps AS signUpTimestamp,
//         number_of_login AS loginCount,
//         logout_timestamps AS lastLogoutTimestamp
//       FROM users
//     `);
//     return rows;
//   } catch (error) {
//     throw new Error('Error fetching users: ' + error.message);
//   }
// };

export default {
  createUser,
  checkEmailExist,
  findUserByToken,
  updateUserByToken,
  findByEmail,
  comparePassword,
  findById,
  updateUserName,
  updatePassword,
  createUserActivity,
  updateToken,
  // findOrCreateUser,
  // getTotalUsers,
  // getActiveSessionsToday,
  // getAverageActiveSessions,
  // getAllUsers,
};
