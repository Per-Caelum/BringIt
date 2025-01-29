const express = require("express");
const app = express();
const PORT = 3000;

require("dotenv").config();

/**
 * Middleware to log HTTP requests in 'dev' format using Morgan.
 */
app.use(require("morgan")("dev"));

/**
 * Middleware to parse incoming JSON request bodies.
 */
app.use(express.json());

/**
 * Routes for handling user-related API requests.
 * This will forward requests to the 'users' API router.
 */
app.use("/users", require("./api/users"));

/**
 * Middleware to handle requests to undefined endpoints.
 * Returns a 404 status code and a message indicating that the endpoint was not found.
 */
app.use((req, res, next) => {
  next({ status: 404, message: "Endpoint not found." });
});

/**
 * Error handling middleware to catch and handle errors.
 * Logs the error and responds with the appropriate status code and message.
 */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status ?? 500);
  res.json(err.message ?? "Sorry, something broke :(");
});

/**
 * Starts the Express application and listens on the specified port.
 * Logs a message once the server is up and running.
 */
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}...`);
});
