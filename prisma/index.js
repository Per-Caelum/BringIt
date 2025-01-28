const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');

// Created model for user login credentials without changing database schema
const prisma = new PrismaClient().$extends({
  model: {
    user: {
      async register(email, password) {
        const hash = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
          data: { email, password: hash },
        });
        return user;
      },
      async login(email, password) {
        const user = await prisma.user.findUniqueOrThrow({
          where: { email },
        });
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) throw Error('Invalid Password');
        return user;
      },
    },
  },
});
module.exports = { prisma };
