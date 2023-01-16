/** User related routes. */
const jsonschema = require("jsonschema");

const User = require("../models/user");
const express = require("express");
const router = new express.Router();
const { UnauthorizedError, NotFoundError } = require("../helpers/expressError");
const { authUser, requireLogin, requireAdmin, requireOwnUserOrAdmin } = require("../middleware/auth");
const userUpdateSchema = require("../schemas/userUpdate.json");

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
  let username = req.params.username;

  let user = await User.get(username);

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

// FIXES BUG #3 - removed requireAdmin middleware
router.patch("/:username", authUser, requireLogin, async function (
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

  // FIXES BUG #1 - Begin
  const validator = jsonschema.validate(
    fields,
    userUpdateSchema,
    { required: true }
  );

  if (!validator.valid) {
    const errs = validator.errors.map(e => e.stack);
    throw new UnauthorizedError(errs);
  }
  // FIXES BUG #1 - End

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

module.exports = router;;
