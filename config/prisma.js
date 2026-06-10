const prisma = require("@prisma/client");

const api = new prisma.PrismaClient();

module.exports = api;