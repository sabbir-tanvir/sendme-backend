const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  // email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};
UserSchema.methods.matchPassword = function (enteredPassword) {
  return enteredPassword === this.password;
};

module.exports = mongoose.model("User", UserSchema);
