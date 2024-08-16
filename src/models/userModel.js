import dbPool from '../config/database.js';
import bcrypt from 'bcrypt';

const connection = await dbPool.getConnection();

const createUser = async (
  username,
  email,
  password,
  token,
  verified,
  createdAt,
  isOAuth
) => {
  let shouldCommit = false;
  try {
    await connection.query(
      'INSERT INTO users (username, email, password, token, verified, createdAt, isOAuth) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [username, email, password, token, verified, createdAt, isOAuth]
    );

    await connection.commit();
    shouldCommit = true;
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
  const [rows] = await connection.query('SELECT * FROM users WHERE email = ?', [
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

  await connection.query(
    'UPDATE users SET verified = ?, token = ? WHERE token = ?',
    [verified, null, token]
  );
};

const updateToken = async (updates) => {
  const { email, token } = updates;

  await connection.query('UPDATE users SET token = ? WHERE email = ?', [
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

const setPassword = async ({ id, newPassword, isOAuth }) => {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  try {
    await connection.query(
      'UPDATE users SET password = ?, isOAuth = ? WHERE id = ?',
      [hashedPassword, isOAuth, id]
    );
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
    connection.rollback();
    console.error('Error at createUserActivity', error);
    throw new Error(error);
  }
};

const getTotalUsers = async () => {
  const [rows] = await connection.query(
    'SELECT COUNT(*) AS totalUsers FROM users'
  );
  return rows[0].totalUsers;
};

const getUsersDashboard = async () => {
  try {
    const [rows] = await connection.query(`
      SELECT 
          u.email,
          u.username,
          u.createdAt,
          COUNT(CASE WHEN ua.action = 'login' THEN 1 END) AS login_count,
          MAX(CASE WHEN ua.action = 'logout' THEN ua.timestamps END) AS last_logout
      FROM 
          users u
      LEFT JOIN 
          user_activities ua ON u.id = ua.userId
      GROUP BY 
          u.email, u.username, u.createdAt;
    `);
    return rows;
  } catch (error) {
    throw new Error('Error fetching users: ' + error.message);
  }
};

const findOrCreateUser = async (profile) => {
  let shouldCommit = false;
  try {
    const [emailExist] = await connection.query(
      'SELECT * FROM users WHERE email = ?',
      [profile.emails[0].value]
    );

    if (emailExist.length > 0) {
      return emailExist[0];
    } else {
      // Check if user exist using facebook or google
      const [rows] = await connection.query(
        'SELECT * FROM users WHERE (facebookId = ? AND googleId IS NULL) OR (facebookId IS NULL AND googleId = ?)',
        [profile.facebookId, profile.googleId]
      );

      if (rows.length > 0) {
        return rows[0];
      } else {
        // Register using facebook
        if (profile.facebookId) {
          await connection.query(
            'INSERT INTO users (username, email, facebookId, verified, createdAt, isOAuth) VALUES (?, ?, ?, ?, ?, ?)',
            [
              profile.displayName,
              profile.emails[0].value,
              profile.facebookId,
              profile.verified,
              profile.createdAt,
              profile.isOAuth,
            ]
          );
        }
        // Register using google
        if (profile.googleId) {
          await connection.query(
            'INSERT INTO users (username, email, googleId, verified, createdAt, isOAuth) VALUES (?, ?, ?, ?, ?, ?)',
            [
              profile.displayName,
              profile.emails[0].value,
              profile.googleId,
              profile.verified,
              profile.createdAt,
              profile.isOAuth,
            ]
          );
        }
        await connection.commit();
        shouldCommit = true;
        return { ...profile };
      }
    }
  } catch (error) {
    if (!shouldCommit) {
      await connection.rollback();
    }
    console.error('Transaction failed, rolled back.', error);
    throw new Error(error);
  } finally {
    if (connection) connection.release();
  }
};

const checkAndUpdateSession = async (id, req, res, next) => {
  const checkQuery = `SELECT id, session_start FROM sessions WHERE user_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1`;
  const today = new Date().toDateString();

  try {
    const [results] = await connection.query(checkQuery, [id]);

    // Check if user has logged-in
    if (results.length > 0) {
      const lastSession = results[0];
      const lastSessionDate = new Date(
        lastSession.session_start
      ).toDateString();

      if (lastSessionDate !== today) {
        // If user has logged in in the previous day but hasn't logged out yet
        const endOfPreviousDaya = new Date(lastSession.session_start);
        endOfPreviousDaya.setHours(23, 59, 59, 999);

        // Update query for session_end for user who hasn't logout during the day
        const updateQuery = 'UPDATE sessions SET session_end = ? WHERE id = ?';
        connection.query(
          updateQuery,
          [endOfPreviousDaya, lastSession.id],
          (err, updateResults) => {
            if (err) throw err;

            // Create new session in the new day
            insertNewSession(id, new Date(), res, next);
          }
        );
      } else {
        // If the session is still on the same day, just continue with existing session
        next();
      }
    } else {
      // No active session found, insert a new session
      insertNewSession(id, new Date(), res, next);
    }
  } catch (error) {
    console.error('Error at checkAndUpdateSession', error);
    throw new Error(error);
  } finally {
    connection.release();
  }
};

const insertNewSession = async (user_id, session_start, res, next) => {
  const insertQuery = `INSERT INTO sessions (user_id, session_start) VALUES (?,?)`;
  try {
    await connection.query(insertQuery, [user_id, session_start]);
    next();
  } catch (error) {
    console.error('Error at insertNewSession', error);
    throw new Error(error);
  } finally {
    connection.release();
  }
};

const updateSessionEnd = async ({ userId, session_end }) => {
  const checkQuery = `SELECT id, session_start FROM sessions WHERE user_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1`;
  const updateQuery = 'UPDATE sessions SET session_end = ? WHERE id = ?';

  try {
    const [results] = await connection.query(checkQuery, [userId]);

    const [updateResult] = await connection.query(updateQuery, [
      session_end,
      results[0].id,
    ]);

    if (updateResult.affectedRows === 0) {
      throw new Error('Failed to update session');
    }
  } catch (error) {
    connection.rollback();
    console.error('Error at updateSession', error);
    throw new Error(error);
  }
};

const updateSessionLogin = async (userId, next) => {
  const checkQuery = `SELECT id, session_start, session_end FROM sessions WHERE user_id = ? ORDER BY session_start DESC LIMIT 1`;
  const updateQuery = 'UPDATE sessions SET session_end = ? WHERE id = ?';

  try {
    const [results] = await connection.query(checkQuery, [userId]);

    // User very first login
    if (results.length === 0) {
      next();
    } else {
      const [updateResult] = await connection.query(updateQuery, [
        null,
        results[0].id,
      ]);

      if (updateResult.affectedRows === 0) {
        throw new Error('Failed to update session');
      }
    }
  } catch (error) {
    connection.rollback();
    console.error('Error at updateSession', error);
    throw new Error(error);
  }
};

const logoutUser = async (id) => {
  try {
    await connection.beginTransaction();

    const user = await findById(id);
    if (!user) {
      await connection.rollback();
      return res.status(404).json({ message: 'User not found' });
    }

    await createUserActivity({
      userId: id,
      action: 'logout',
      timestamps: new Date(),
    });

    await updateSessionEnd({
      userId: id,
      session_end: new Date(),
    });

    await connection.commit();
  } catch (error) {
    await connection.rollback();
    console.error('Error during logoutUser transaction', error);
    throw error;
  } finally {
    connection.release();
  }
};

const countActiveSession = async () => {
  const [rows] = await connection.query(
    'SELECT COUNT(DISTINCT user_id) AS active_users_today FROM sessions WHERE (session_end IS NULL OR DATE(session_end) >= CURDATE()) AND DATE(session_start) >= CURDATE()'
  );

  return rows[0].active_users_today;
};

const countAverageSession = async () => {
  const [rows] = await connection.query(
    'SELECT ROUND(AVG(daily_active_users)) AS avg_active_users_last_7_days FROM (SELECT DATE(session_start) AS session_date, COUNT(DISTINCT user_id) AS daily_active_users FROM sessions WHERE session_start >= CURDATE() - INTERVAL 7 DAY GROUP BY DATE(session_start)) AS daily_counts;'
  );

  return rows[0].avg_active_users_last_7_days;
};

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
  getTotalUsers,
  getUsersDashboard,
  findOrCreateUser,
  checkAndUpdateSession,
  logoutUser,
  countActiveSession,
  countAverageSession,
  updateSessionLogin,
  setPassword,
};
