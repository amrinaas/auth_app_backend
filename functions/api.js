import express from 'express';
import serverless from 'serverless-http';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import passport from '../src/config/passport.js';
import session from 'express-session';
import userRoutes from '../src/routes/userRoutes.js';
import router from '../src/routes/userRoutes.js';

const app = express();
const PORT = process.env.PORT || 5000;

// MIDDLEWARES
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    credentials: true,
    origin: process.env.WEBSITE,
    optionsSuccessStatus: 200,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use('/user', userRoutes);

app.get('/', (req, res) =>
  res.send({
    message: 'App is running',
  })
);

// Use the correct path for Netlify functions
app.use('/.netlify/functions/api', userRoutes);

// Export the serverless handler
export const handler = serverless(app);

// START SERVER (for local development)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}
