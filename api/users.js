const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { prisma } = require("../prisma");

/**
 * Generates a JSON Web Token (JWT) for a user.
 * @param {string} id - The user ID to include in the token payload.
 * @returns {string} - The generated JWT.
 */
function createToken(id) {
  const JWT_SECRET = process.env.JWT_SECRET;
  return jwt.sign({ id }, JWT_SECRET, { expiresIn: "2h" });
}

/**
 * Middleware to check if a valid JWT is present in the request header.
 * If a token is present, it will decode the token and attach the user to the request object.
 * Otherwise, it will pass the request along to the next middleware without any modifications.
 */
router.use(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.slice(7);
  if (!token) {
    return next();
  }
  try {
    const { id } = jwt.verify(token, process.env.JWT_SECRET);
    const user = await prisma.user.findUniqueOrThrow({ where: { id } });
    req.user = user;
    next();
  } catch (e) {
    next(e);
  }
});

/**
 * Handles user registration.
 * Hashes the user's password and stores their information in the database.
 * Returns a token on successful registration.
 */
router.post("/register", async (req, res, next) => {
  const { email, password, firstname, lastname } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        firstname,
        lastname,
      },
    });

    res.status(201).json({ token: createToken(user.id) });
  } catch (e) {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json("Email already exists");
    }
    next(e);
  }
});

/**
 * Handles user login.
 * Verifies the user's credentials and returns a token if successful.
 */
router.post("/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.login(email, password);
    const token = createToken(user.id);
    res.json({ token });
  } catch (e) {
    next(e);
  }
});

/**
 * Middleware to ensure the user is authenticated before accessing a route.
 * If no user is attached to the request, it returns a 401 Unauthorized error.
 */
function authenticate(req, res, next) {
  if (!req.user) {
    return next({ status: 401, message: "Please log in first." });
  }
  next();
}

/**
 * Retrieves information about the authenticated user.
 * This route requires authentication via the `authenticate` middleware.
 */
router.get("/aboutMe", authenticate, async (req, res, next) => {
  try {
    const { id, firstname, lastname, email } = req.user;
    res.json({ id, firstname, lastname, email });
  } catch (e) {
    next(e);
  }
});

//gets all users
router.get("/", authenticate, async (req, res, next) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (e) {
    next(e);
  }
});
//gets user by id
router.get("/:id", authenticate, async (req, res, next) => {
  const { id } = req.params;
  try {
    const user = await prisma.user.findUniqueOrThrow({ where: { id } });
    res.json(user);
  } catch (e) {
    next(e);
  }
});

router.delete("/:id", authenticate, async (req, res, next) => {
  const { id } = req.params;
  try {
    const user = await prisma.user.delete({ where: { id } });
    res.json(user);
  } catch (e) {
    next(e);
  }
});

router.put("/:id", authenticate, async (req, res, next) => {
  const { id } = req.params;
  const { email, password, firstname, lastname } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.update({
      where: { id },
      data: { email, password: hashedPassword, firstname, lastname },
    });
    res.json(user);
  } catch (e) {
    next(e);
  }
});

module.exports = router;
