const router = require('express').Router()

const jwt = require('jsonwebtoken')

const bcrypt = require('bcryptjs')

const User = require('../models/userModel')

const auth = require('../middleware/auth')

router.post('/register',async(req,res)=>{
    try{
        const {email,password} = req.body
        const existingUser = await User.findOne({email : email})
        if(existingUser){
            return res.status(400).send({msg : "User account already exists"})
        }
        const salt = await bcrypt.genSalt()
        const passwordHash = await bcrypt.hash(password,salt)
        const user = new User({
            email,
            password : passwordHash
        })
        const savedUser = await user.save()
        res.json(savedUser)
    }catch(err){
        res.status(500).json({error : err.message})
    }
})

router.post('/login', async (req,res)=>{
    try{
        const {email,password} = req.body
        const user = await User.findOne({email : email})
        if(!user){
            return res.status(400).send({msg : "User account does not exists"})
        }
        const isMatch = await bcrypt.compare(password,user.password)
        if(!isMatch){
            return res.status(400).send({msg : "Invalid email id or password"})
        }
        const token = jwt.sign({id : user._id}, process.env.JWT_SECRET)
        res.json({
            token,
            user : {
                id : user._id
            }
        })
    }catch(err){
        res.status(500).json({error  : err.message})
    }
    
})

router.get('/', auth, async (req, res) => {
    try {
      const user = await User.findById(req.user)
      res.json({
        id: user._id,
        email: user.email,
        password: user.password
      })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
})

router.put('/updatepassword/:id',async (req,res) =>{
    try {
        const id = req.params.id
        const user = await User.findById(id)
        const salt = await bcrypt.genSalt()
        const passwordHash = await bcrypt.hash(user.password,salt)
        const updatedUser = await User.update({_id : user._id},{password : passwordHash})
        res.json(updatedUser)
      } catch (err) {
        res.status(500).json({ error: err.message })
      }
})

module.exports = router