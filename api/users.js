const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { prisma } = require('../prisma');


function createToken(id) {
  const JWT_SECRET = process.env.JWT_SECRET;
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: '2h' });
}

router.use(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.slice(7);
  if (!token) {
    return next();
  }
  try {
    const { id } = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUniqueOrThrow({ where: { id } });
    req.user = user;
    next();
  } catch (e) {
    next(e);
  }
});

router.post('/register', async (req, res, next) => {
  const { email, password, firstname, lastname } = req.body;
  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: await bcrypt.hash(password, 10),
        firstname,
        lastname,
      },
    });
    res.status(201).json({ token: createToken(user.id) });
  } catch (e) {
    next(e);
  }
});

router.post('/login', async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.login(email, password);
    const token = createToken(user.id);
    res.json({ token });
  } catch (e) {
    next(e);
  }
});

function authenticate(req, res, next) {
  if (!req.user) {
    return next({ status: 401, message: 'Please log in first.' });
  }
  next();
}

module.exports = router;

bcrypt.genSalt;
