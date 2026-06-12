import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { UserRepository } from './user-repository.js'

const app = express()
const PORT = process.env.PORT ?? 3000
const SECRET_JWT_KEY = 'super-secreto-seguro-jwt-para-la-practica-de-backend'

app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

// Middleware de verificación de sesión global
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  if (token) {
    try {
      const data = jwt.verify(token, SECRET_JWT_KEY)
      req.session.user = data
    } catch (error) {
      // Sesión nula si expira o el token es inválido
    }
  }
  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', { user })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Acceso no autorizado. Inicia sesión primero.')
  res.render('protected', { user })
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (error) {
    res.status(400).send({ error: error.message })
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    
    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_JWT_KEY,
      { expiresIn: '1h' }
    )

    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60
      })
      .send({ user })
  } catch (error) {
    res.status(401).send({ error: error.message })
  }
})

app.post('/logout', (req, res) => {
  res.clearCookie('access_token').send('Cierre de sesión exitoso')
})

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`)
})
