// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const {checkPasswordLength, checkUsernameFree,checkUsernameExists} = require('./auth-middleware')
const router = require('express').Router()
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register',checkUsernameFree, checkPasswordLength,async(req,res,next)=>{
  //hash password 
  //import bycrypt
  const {username, password} = req.body
  const hash = bcrypt.hashSync(password,12)
  
  const newUser = {
    username: username,
    password: hash
  }
  try{

    const created = await Users.add(newUser)
    res.status(200).json(created)

  }
  catch(err){
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */



  router.post('/login', checkUsernameExists, checkPasswordLength, async (req,res,next)=>{
    //check username and passwords then add cookie session
    const {username,password}= req.body
    try{
      const user = await Users.findBy({username:username})

      if(user && bcrypt.compareSync(password,user.password)){//compare that the two passwords match compareSync(incomingPassword,databasePassword)
        
        req.session.user = user; // now that we've set a user the server will automatically send a cookie back

        res.status(200).json({message:`Welcome ${user.username}`})
      }
      else{
        res.status(401).json('invalid creds')
      }

    }
    catch(err){
      next(err)
    }
  })

  router.get('/logout', (req, res)=>{
    //delete session 
    if(req.session){
      req.session.destroy(err => {
        if(err){
          res.send('error logging out')
        }
        else{
          res.send('Goodbye')
        }
      })
    }
  })

  router.use((err,req,res)=>{
    res.status(err.status || 500)
    .json({
        message:err.message,
        stack: err.stack
      })
  })

 
// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router
