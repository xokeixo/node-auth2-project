const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets");
const { findBy } = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) {
    return next({ 
      status: 401, 
      message: 'Token required' 
    })
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ 
          status: 401, 
          message: `Token invalid` 
        })
      } else {
        req.decodedJwt = decoded
        next()
      }
    })
  }
}

const only = (role_name) => (req, res, next) => {
  // let decodedJwt = req.decodedJwt
  if (role_name === req.decodedJwt.role_name) {
    next()
  } else {
    next({
      status: 403,
      message: 'This is not for you' 
    })
  }
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await findBy({ 
      username: req.body.username
    })
    if(!user){
      next({ 
        status:422, 
        message:"Invalid credentials"
      })
    } else{
      req.user = user
      next()
    }
 } catch (err) {
   next(err)
   }
}


const validateRoleName = (req, res, next) => {
  if(!req.body.role_name || req.body.role_name === "") {
    req.body.role_name = 'student'
    req.body.role_name.trim()
    next()
  } else if (req.body.role_name === 'admin') {
    res.status(422).json({
      message: 'Role name can not be admin'
    })
  } if (req.body.role_name.trim().length > 32 ) {
    res.status(422).json({ 
      message: 'Role name can not be longer than 32 chars'
    })
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
