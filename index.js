require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { default: mongoose } = require('mongoose')
const User = require('./models/User')
const bcrypt = require('bcrypt');
const app = express()
const jwt = require('jsonwebtoken')

const salt = bcrypt.genSaltSync(10)
const secret = bcrypt.genSaltSync(10)

app.use(cors({credentials: true, origin: `${process.env.HOST}`}))
app.use(express.json())

mongoose.connect(`${process.env.DATABASE_URL}`)


// Create a new User
app.post('/register', async (req, res) => {
  const {username, password} = req.body
  try {
    
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    })
    res.json(userDoc)
  } catch (err) {
    res.status(400).json(err)
  }
})

app.post('/login', async (req, res) => {
  const {username, password} = req.body

  // Grab the user
  const userDoc = await User.findOne({username})

  const passOk = bcrypt.compareSync(password, userDoc.password)

  if(passOk) {
    jwt.sign({username, id: userDoc._id}, secret, {}, (err, token) => {
      if(err) throw err
      res.cookie('token', token).json('ok')
    })
  } else {
    res.status(400).json('Wrong credientials!')
  }
})


app.listen(`${process.env.PORT}`)