// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
const router = require('express').Router()
const { restricted } = require('../auth/auth-middleware')
const Users = require('./users-model')

/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */

  router.get('/', restricted, async (req,res,next)=>{
    try{
      const data = await Users.find()
      res.status(200).json(data)
    }
    catch(err){next(err)}
  })

  router.use((err, req, res)=>{
    res.status(err.status || 500).json({
      message:err.message, 
      stack:err.stack
    })
  })


// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router