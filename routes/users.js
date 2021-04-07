const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

require('dotenv').config();
const User = require('../models/user.js');

const jwtSecret = process.env.JWT_SECRET_TOKEN;
const router = express.Router();

//Sign Up
router.post('/register', (req, res) => {
  const newUser = User({
    name: req.body.name,
    phoneNumber: req.body.phoneNumber,
    email: req.body.email,
    password: req.body.password,
    createdAt: Date.now(),
  });
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (error, hash) => {
      // Encrypting the password
      newUser.password = hash;
      newUser
        .save()
        .then(() => {
          const jwtpayload = {
            id: newUser.id,
            name: newUser.name,
          };
          const token = jwt.sign(jwtpayload, jwtSecret);
          const response = {
            token,
          };
          res.status(201).send(response);
        })
        .catch((errorInStoring) => {
          res.status(400).send(`unable to save to database ${errorInStoring}`);
        });
    });
  });
});

//Login
router.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
    const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    const jwtpayload = {
      id: user.id,
      name: user.name,
    };
    const token = jwt.sign(jwtpayload, jwtSecret);
    const response = {
      token,
    };
    res.status(201).send(response);
  });
});

//About
router.get('/me', (req, res) => {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
    User.findById(decoded.id, (error, user) => {
      if (error) return res.send(err);
      return res.status(200).send(user);
    });
  });
});

module.exports = router;
