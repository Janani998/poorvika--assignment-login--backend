const express = require('express')

const bodyParser = require('body-parser')

const mongoose = require('mongoose')

const cors = require('cors')

require('dotenv').config()

const app = express()

app.use(cors())

app.use(express.json())

app.use(bodyParser.urlencoded({extended : true}))

app.use(bodyParser.json())


const port = process.env.PORT
const mongodbURI = process.env.MONGODB_URI 

app.listen(port, ()=> console.log(`App listening to port ${port}`))

mongoose.connect(mongodbURI , {useNewUrlParser : true, useUnifiedTopology : true})
.then(() => console.log("connected to database"))
.catch(err => console.log("error occcured due to",err))

app.use('/users', require('./routes/user'))