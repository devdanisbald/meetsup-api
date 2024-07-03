const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = "your_secret_key"; // Replace with your actual secret key
const meetupsFile = "./meetups.json";
const usersFile = "./users.json";

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.message = message;
  }
}

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Helper function to read users from file
const readUsers = () => {
  try {
    const data = fs.readFileSync(usersFile, "utf8");
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
};

// Helper function to write users to file
const writeUsers = (users) => {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), "utf8");
};

// Helper function to read meetups from file
const readMeetups = () => {
  try {
    const data = fs.readFileSync(meetupsFile, "utf8");
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
};

// Helper function to write meetups to file
const writeMeetups = (meetups) => {
  fs.writeFileSync(meetupsFile, JSON.stringify(meetups, null, 2), "utf8");
};

// GET /meetups - Fetch meetups
app.get("/meetups", (req, res) => {
  const meetups = readMeetups();
  res.json(meetups);
});


// POST /meetups - Create a new meetup
app.post("/meetups", authenticateToken, (req, res, next) => {
  const { title, summary, address } = req.body;
  if (
    !title ||
    !summary ||
    !address ||
    title.trim() === "" ||
    summary.trim() === "" ||
    address.trim() === ""
  ) {
    return next(new HttpError(400, 'Title, summary, and address must not be empty'));
  }

  const meetups = readMeetups();
  const newMeetup = {
    id: uuidv4(),
    title: title.trim(),
    summary: summary.trim(),
    address: address.trim(),
  };
  meetups.push(newMeetup);
  writeMeetups(meetups);

  res.status(201).json(newMeetup);
});

// PATCH /meetups/:id - Update existing meetup
app.patch("/meetups/:id", authenticateToken, (req, res, next) => {
  const { id } = req.params;
  const { title, summary, address } = req.body;
  const meetups = readMeetups();

  const index = meetups.findIndex((meetup) => meetup.id === id);

  if (index === -1) {
    return next(new HttpError(404, 'Meetup not found'));
  }

  if (title !== undefined && title.trim() === "") {
    return next(new HttpError(400, 'Title must not be empty'));
  }
  if (summary !== undefined && summary.trim() === "") {
    return next(new HttpError(400, 'Summary must not be empty'));
  }
  if (address !== undefined && address.trim() === "") {
    return next(new HttpError(400, 'Address must not be empty'));
  }

  const updatedMeetup = {
    ...meetups[index],
    ...(!!title !== false ? { title: title.trim() } : {}),
    ...(!!summary !== false ? { summary: summary.trim() } : {}),
    ...(!!address !== false ? { address: address.trim() } : {}),
  };
  meetups[index] = updatedMeetup;
  writeMeetups(meetups);

  res.json(updatedMeetup);
});

// DELETE /meetups/:id - Delete existing meetup
app.delete("/meetups/:id", authenticateToken, (req, res, next) => {
  const { id } = req.params;
  let meetups = readMeetups();
  const index = meetups.findIndex((meetup) => meetup.id === id);

  if (index === -1) {
    return next(new HttpError(404, 'Meetup not found'));
  }

  meetups = meetups.filter((meetup) => meetup.id !== id);
  writeMeetups(meetups);

  res.status(204).send();
});

// POST /signup - Create a new user
app.post("/signup", async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new HttpError(400, 'Email and password are required'));
  }

  const users = readUsers();
  if (users.some((user) => user.email === email)) {
    return next(new HttpError(409, 'Email already in use'));
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { email, password: hashedPassword };
  users.push(newUser);
  writeUsers(users);

  res.status(201).json({ message: "User created successfully" });
});

// POST /login - Authenticate a user
app.post("/login", async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new HttpError(400, 'Email and password are required'));
  }

  const users = readUsers();
  const user = users.find((user) => user.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return next(new HttpError(401, 'Invalid email or password'));
  }

  const accessToken = jwt.sign({ email: user.email }, SECRET_KEY, {
    expiresIn: "1h",
  });
  res.json({ accessToken });
});

// Apply the authentication middleware to all meetup routes
app.use("/meetups", authenticateToken);

// Generic error handling middleware
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'An unexpected error occurred';
  res.status(statusCode).json({ message });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
