const passport = require('passport');
const crypto = require('crypto');
const mongoose = require('mongoose');

const User = mongoose.model('User');
const promisify = require('es6-promisify');
const mail = require('../handlers/mail');

exports.login = passport.authenticate('local', {
  failureRedirect: '/login',
  failureFlash: 'Unsuccessful login!',
  successRedirect: '/',
  successFlash: 'Successful login!'
});

exports.logout = (req, res) => {
  req.logout();
  req.flash('success', 'Successful logout! 👋');
  res.redirect('/');
};

exports.isLoggedIn = (req, res, next) => {
  // first check if the user is authenticated
  if (req.isAuthenticated()) {
    next(); // carry on! They are logged in!
    return;
  }
  req.flash('error', 'Oops! You should be logged in to do that!');
  res.redirect('/login');
};

exports.isAdmin = (req, res, next) => {
  // first check if the user is administrator
  if (req.user.level === 10) {
    next(); // carry on! They are admins
    return;
  }
  req.flash('error', 'You do not have enough permissions to do that!');
  res.redirect('/');
};

exports.forgot = async (req, res) => {
  // 1. See if a user with that email exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    req.flash('error', 'No profiles found with that email');
    return res.redirect('/login');
  }
  // 2. Set reset tokens and expiry on their account
  user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour from now
  await user.save();
  // 3. Send them an email with the token
  const resetURL = `http://${req.headers.host}/account/reset/${
    user.resetPasswordToken
  }`;
  await mail.send({
    user,
    filename: 'password-reset',
    subject: 'Reset password',
    resetURL
  });
  req.flash('success', 'Check your email for password reset link');
  // 4. redirect to login page
  res.redirect('/login');
};

exports.reset = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });
  if (!user) {
    req.flash('error', 'Password reset link is expired or not valid');
    return res.redirect('/login');
  }
  // if there is a user, show the rest password form
  res.render('reset', { title: 'Forgoten password' });
};

exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body['password-confirm']) {
    next(); // keepit going!
    return;
  }
  req.flash('error', 'Passwords does not match!');
  res.redirect('back');
};

exports.update = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
    req.flash('error', 'Password reset link is expired or not valid');
    return res.redirect('/login');
  }

  const setPassword = promisify(user.setPassword, user);
  await setPassword(req.body.password);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  const updatedUser = await user.save();
  await req.login(updatedUser);
  req.flash(
    'success',
    '💃 Super! You can use your new password! You are logged in!'
  );
  res.redirect('/');
};

exports.updateExistingPassword = async (req, res, next) => {
  const user = await User.findOne({ _id: req.user._id });

  if (req.body.password) {
    const setPassword = promisify(user.setPassword, user);
    await setPassword(req.body.password);
    const updatedUser = await user.save();
    await req.login(updatedUser);
    req.flash(
      'success',
      '💃 Super! You can use your new password! You are logged in!'
    );
  }
  return next();
};
