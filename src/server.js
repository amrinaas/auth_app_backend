import express from 'express';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import passport from './config/passport.js';
import session from 'express-session';
import userRoutes from './routes/userRoutes.js'; // Ensure the path is correct

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
app.use(cors({ credentials: true, origin: true }));
app.use(passport.initialize());
app.use(passport.session());

app.use('/user', userRoutes);

app.get('/', (req, res) =>
  res.send({
    message: 'App is running',
  })
);

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
