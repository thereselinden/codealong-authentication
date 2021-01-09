import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'

// Connect mongoose conntector to our database 
const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
mongoose.connect(mongoUrl, {useNewUrlParser: true, useUnifiedTopology: true})
mongoose.Promise = Promise

const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    unique: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex")
  }
})

//Middleware function that checks accessToken when register a user stored in the header.
//Find a user where the accessToken matches a user.
const authenticateUser = async (req, res, next ) => {
  const user = await User.findOne({ accessToken: req.header("Authorization")})
  if (user) {
    req.user = user
    next() //to continue execute protected endpoints
  } else {
    res.status(401).json({ loggedOut: true })
  }
}

// Defines the port the app will run on. Defaults to 8080, but can be 
// overridden when starting the server. For example:
//
//   PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

app.post('/users', async (req, res) => {
  try {
    const { name, email, password } = req.body
    //DO NOT STORE PASSWORD IN PLAIN TEXT
    const user = new User({ name, email, password: bcrypt.hashSync(password)})
    const newUser = await user.save()
    res.status(201).send({ id: newUser._id, accessToken: newUser.accessToken })
  } catch (err) {
    res.status(400).send({
      errors: {
        message: err.message,
        error: err, 
      },
    });
  }
})

app.get('/secrets', authenticateUser)
app.get('/secrets', (req, res) => {
  res.json({secret: "This is a super secret message"})
})


//first password argument is the clear text password
//the second password argument is the hasched packed password we have in the db
app.post('/sessions', async (req, res) => {
  const user = await User.findOne({ email: req.body.email })
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken})
  } else {
    //if user not found or password does not match
    res.json({ notFound: true })
  }
})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
