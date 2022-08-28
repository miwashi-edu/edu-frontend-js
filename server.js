require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const healthcheck = require('healthcheck')

//const bodyparser = reuire('bodyparser')

//console.log(process.env)
const PORT = process.env.PORT || 3000
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET

console.log('****** NODE_ENV *******')
console.log(process.env.NODE_ENV)
console.log('****** NODE_ENV *******')

let refreshTokens = []

const app = express()
app.use(express.json())
app.use('/healthcheck', require('./routes/healthcheck.routes'));

app.get("/", (req ,res) => {
   headers={"cache-control":  "no-cache"}
   body={"status": "available"}
   res.status(200).json(body)
})

app.post("/authenticate", (req ,res) => {
    headers={"cache-control":  "no-cache"}
    const username = req.body.username
    const user = { name: username }
    const accessToken = generateAccessToken(user)
    const refreshToken = generateRefreshToken(user)
    res.status(200).json(
        {
            accessToken: accessToken, 
            refreshToken: refreshToken
        }
    )
 })

 app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    console.log(refreshToken)
    
    if(refreshToken==null) return res.sendStatus(401)

    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(401)
    
    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)

        const accessToken = generateAccessToken({ name: user.name}, ACCESS_TOKEN_SECRET)
        res.json({accessToken: accessToken})
    })
 })

 app.delete('logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => req.body.token)
    res.sendStatus(204)
 })

 app.get("/secret", authenticateToken, (req ,res) => {
    console.log("In secret")
    res.json({user: req.user.name})
 })

app.listen(PORT , ()=>{
     console.log(`STARTED LISTENING ON PORT ${PORT}`)
});

function generateRefreshToken(user){
    const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken)
    return refreshToken
}

function generateAccessToken(user){
    const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET,
        {expiresIn: '15s'}
    )
    return accessToken
}

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(token == null) return  res.sendStatus(401)

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        req.user = user
        next()
    })
}