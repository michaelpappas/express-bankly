/** User related routes. */

const User = require("../models/user");
const express = require("express");
const router = new express.Router();
const { UnauthorizedError } = require("../helpers/expressError");
const { authUser, requireLogin, requireAdmin } = require("../middleware/auth");

/** GET /
 *
 * Get list of users. Only logged-in users should be able to use this.
 *
 * It should return only *basic* info:
 *    {users: [{username, first_name, last_name}, ...]}
 */

router.get("/", authUser, requireLogin, async function (req, res, next) {
  let users = await User.getAll();
  return res.json({ users });
}); // end

/** GET /[username]
 *
 * Get details on a user. Only logged-in users should be able to use this.
 *
 * It should return:
 *     {user: {username, first_name, last_name, phone, email}}
 *
 * If user cannot be found, return a 404 err.
 */

router.get("/:username", authUser, requireLogin, async function (
  req,
  res,
  next,
) {
  let user = await User.get(req.params.username);
  return res.json({ user });
});

/** PATCH /[username]
 *
 * Update user. Only the user themselves or any admin user can use this.
 *
 * It should accept:
 *  {first_name, last_name, phone, email}
 *
 * It should return:
 *  {user: all-data-about-user}
 *
 * If user cannot be found, return a 404 err. If they try to change
 * other fields (including non-existent ones), an error should be raised.
 */

router.patch("/:username", authUser, requireLogin, requireAdmin, async function (
  req,
  res,
  next,
) {
  if (!res.locals.isAdmin && res.locals.username !== req.params.username) {
    throw new UnauthorizedError("Only that user or admin can edit a user.");
  }

  // get fields to change; remove token so we don't try to change it
  let fields = { ...req.body };
  delete fields._token;

  let user = await User.update(req.params.username, fields);
  return res.json({ user });
}); // end

/** DELETE /[username]
 *
 * Delete a user. Only a staff user should be able to use this.
 *
 * It should return:
 *   {message: "deleted"}
 *
 * If user cannot be found, return a 404 err.
 */

router.delete("/:username", authUser, requireAdmin, async function (
  req,
  res,
  next,
) {
  User.delete(req.params.username);
  return res.json({ message: "deleted" });
}); // end

module.exports = router;
