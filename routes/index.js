const express = require('express');
const router = express.Router();
const fs = require('fs');
const UserModel = require('../models/user');
const path = require('path');
const jws = require('jws');
const jwt = require('jsonwebtoken');

const publicKey = fs.readFileSync(path.join(__dirname, '../public.key'), 'utf8');
const privateKey = fs.readFileSync(path.join(__dirname, '../private.key'), 'utf8');

router.get('/', function(req, res) {
  res.status(200).json('It`s alive!')
});

// видача токену
router.post('/register', async (req, res) => {
  try {
    const { name, lastName, password, username } = req.body;

    const user = await UserModel.create({name, lastName, password, username})

    if(!user) {
      throw new Error('no user')
    }
    
    const token = jws.sign({
      header: {alg: 'RS256'},
      payload: {name, lastName, username},
      privateKey: privateKey
    }); 

    if(!token) {
      throw new Error('error while creating a token')
    }

    res.cookie('jwt', token, { maxAge: 1000 * 3600 })
    res.status(200).json({token})
  } catch(err) {
    res.status(400).json(err) 
  }
})

router.post('/login', async (req, res) => {
  try {
    const {password, username } = req.body;
    const user = await UserModel.findOne({username})
    if(!user) {throw new Error('wrong pw')}
    user.comparePassword(password, (err, match) => {
      if(err || !match) {
        res.status(400).json('wrong pw') 
      } else {
        const token = jws.sign({
          header: {alg: 'RS256'},
          payload: {name: user.name, lastName: user.lastName, username},
          privateKey: privateKey
        }); 
        if(!token) {res.status(400).json('wrong pw') }
        res.cookie('jwt', token, { maxAge: 1000 * 3600 })
        res.status(200).json({token})
      }
    })
    if(!user) {throw new Error('no user')}
  } catch(err) {res.status(400).json(err) }
})

// захищений роут
router.get('/protectedRoute', async (req, res) => {
  const token = req.cookies['jwt'];
  jwt.verify(token, publicKey,  {algorithms: ['RS256']}, (err, decoded) => {
    if(!decoded || err) {
      res.status(403).json('unathorized')
    }
    res.status(200).json(decoded)
  });
  
})

router.get('/logout', async (req, res) => {
  res.clearCookie('jwt');
  res.status(200).json('logout completed');
})

module.exports = router;
