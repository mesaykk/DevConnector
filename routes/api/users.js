const express = require('express');
const router = express.Router();
const User = require('../../models/User');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');
const validationRegisterInput = require('../../validation/register');
const validationLoginInput = require('../../validation/login');



router.get('/current', passport.authenticate('jwt', {session: false}), (req, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email
  });
}
);

// @route   POST api/users/login
// @desc    Login User
// @access  Public
router.post('/login', (req, res) => {
  const {errors, isValid} =  validationLoginInput(req.body)

  //check for validation
  if (!isValid){
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find user by email
  User.findOne({email})
  .then(user => {
    if (!user){
      return res.status(404)
      .json(errors);
    }

    // check password
    bcrypt.compare(password, user.password)
    .then(isMatch => {
      if (isMatch){
        //User matched
        const payload = {
          id: user.id,
          name: user.name,
          avatar: user.avatar
        };

        jwt.sign(payload, 
          keys.secretOrKey,
          {expiresIn: 3600},
          (err, token) => {
            res.json({
              success: true,
              token: 'Bearer ' + token
            });
          }
        )
      } else {
        return res.status(400)
      .json({password: 'Password does not match.'});
      }
    })
  })
})



// @route   POST api/users/register
// @desc    Register user
// @access  Public
router.post('/register', (req, res) => {
  const {errors, isValid} =  validationRegisterInput(req.body)

  //check for validation
  if (!isValid){
    return res.status(400).json(errors);
  }
  
  User.findOne({email: req.body.email })
    .then(user => {
      if (user) {
        errors.email = 'Email already exists';
        return res.status(400).json(errors);
      } else {
        const avatar = gravatar.url(req.body.email, {
          s: '200',
          r: 'pg',
          d: 'mm'
        });

        const newUser = new User({
          name: req.body.name,
          email: req.body.email,
          avatar,
          password: req.body.password
        });

        bcrypt.genSalt(10, (err, salt) => {
          if (err) throw err;
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser.save()
              .then(user => res.json(user))
              .catch(err => console.log(err));
          });
        });

      }
    } )
    .catch(err => console.log(err));
})

// @route   POST api/users/login
// @desc    Login user
// @access  Public
router.post('/login', (req,res) => {
  const email = req.body.email;
  const password = req.body.password;

  //Find user by email
  User.findOne({email})
    .then(user => {
      if (!user){
        return res.status(404).json({
          email: 'User not found'
        });
      }
    })
    .catch(err => console.log(err));
})

module.exports = router;

