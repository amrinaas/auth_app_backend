import jwt from 'jsonwebtoken';

const generateToken = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
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
    path: '/',
    secure: true,
    sameSite: 'None',
    domain: process.env.DOMAIN,
  });
};

const sendTokens = (res, accessToken, refreshToken) => {
  res.cookie('accessToken', accessToken, {
    httpOnly: false,
    path: '/',
    secure: true,
    sameSite: 'None',
    domain: process.env.DOMAIN,
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    path: '/',
    secure: true,
    sameSite: 'None',
    domain: process.env.DOMAIN,
  });
};

const clearTokens = (res) => {
  res.clearCookie('accessToken', {
    httpOnly: false,
    path: '/',
    secure: true,
    sameSite: 'None',
    expires: new Date(0),
    domain: process.env.DOMAIN,
  });

  res.clearCookie('refreshToken', {
    httpOnly: true,
    path: '/',
    secure: true,
    sameSite: 'None',
    expires: new Date(0),
    domain: process.env.DOMAIN,
  });
};

export { generateToken, sendRefreshToken, sendTokens, clearTokens };
