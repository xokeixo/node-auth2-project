const router = require('express').Router();
const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../secrets'); // use this secret!

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const User = require('../users/users-model');


function buildToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role_name
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

router.post('/register', validateRoleName, (req, res, next) => {
  let user = req.body
  
  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash

  User.add(user)
    .then(newUser => {
      res.status(201).json(newUser)
    })
    .catch(err => {
      res.status(500).json({ message: err.message })
    })
});


router.post('/login', checkUsernameExists, (req, res, next) => {
  if(bcrypt.compareSync(req.body.password ,req.user.password)){
    const token = buildToken(req.user)
      res.json({
        status: 200,
        message: `${req.user.username} is back!`,
        token,
      })
  } else{
    next({ 
      status: 401, 
      message:'Invalid credentials'
    })
  }
});

module.exports = router;
