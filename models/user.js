const bcrypt = require('bcrypt');
const db = require('../db');
const {
  UnauthorizedError,
  NotFoundError,
  BadRequestError,
} = require('../helpers/expressError');
const sqlForPartialUpdate = require('../helpers/partialUpdate');
const { BCRYPT_WORK_FACTOR } = require("../config");

class User {

  /** Register user with data. Returns new user data. */

  static async register({ username, password, first_name, last_name, email, phone }) {
    const duplicateCheck = await db.query(
      `SELECT username
        FROM users
        WHERE username = $1`,
      [username]
    );

    if (duplicateCheck.rows[0])
      throw new BadRequestError(`Duplicate username: ${username}`);

    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const result = await db.query(
      `INSERT INTO users
          (username, password, first_name, last_name, email, phone)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING username, password, first_name, last_name, email, phone`,
      [
        username,
        hashedPassword,
        first_name,
        last_name,
        email,
        phone
      ]
    );

    return result.rows[0];
  }


  /** Is this username + password combo correct?
   *
   * Return all user data if true, throws error if invalid
   *
   * */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username,
                password,
                first_name,
                last_name,
                email,
                phone,
                admin
            FROM users
            WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    } else {
      throw new UnauthorizedError('Cannot authenticate');
    }
  }

  /** Returns list of user info:
   *
   * [{username, first_name, last_name, email, phone}, ...]
   *
   * */

  static async getAll() {
    const result = await db.query(
      `SELECT first_name,
                last_name,
                email,
                phone
            FROM users
            ORDER BY username`
    );
    return result.rows;
  }

  /** Returns user info: {username, first_name, last_name, email, phone}
   *
   * If user cannot be found, should raise a 404.
   *
   **/

  static async get(username) {
    const result = await db.query(
      `SELECT username,
                first_name,
                last_name,
                email,
                phone
         FROM users
         WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];
    debugger;
    if (!user) {
      throw new NotFoundError('No such user'); // FIXES BUG #4 - throw missing
    }

    return user;
  }

  /** Selectively updates user from given data
   *
   * Returns all data about user.
   *
   * If user cannot be found, should raise a 404.
   *
   **/

  static async update(username, data) {
    let { query, values } = sqlForPartialUpdate(
      'users',
      data,
      'username',
      username
    );
    debugger;
    const result = await db.query(query, values);
    const user = result.rows[0];

    if (!user) {
      throw new NotFoundError('No such user');
    }

    return user;
  }

  /** Delete user. Returns true.
   *
   * If user cannot be found, should raise a 404.
   *
   **/

  static async delete(username) {
    const result = await db.query(
      'DELETE FROM users WHERE username = $1 RETURNING username',
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      throw new NotFoundError('No such user');
    }

    return true;
  }
}

module.exports = User;
