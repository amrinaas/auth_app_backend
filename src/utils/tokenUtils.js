import jwt from 'jsonwebtoken';

const generateToken = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  const refreshToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

const sendRefreshToken = (res, token) => {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    path: '/user/:id',
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
};

export { generateToken, sendRefreshToken };
