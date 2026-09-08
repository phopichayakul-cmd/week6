const bcrypt = require("bcryptjs");

const users = [
  { id: 101, username: "alice", role: "student", passwordHash: bcrypt.hashSync("alice123", 10) },
  { id: 102, username: "bob", role: "admin", passwordHash: bcrypt.hashSync("admin123", 10) },
  { id: 103, username: "john", role: "student", passwordHash: bcrypt.hashSync("john123", 10) }
];

module.exports = { users };
