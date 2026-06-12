import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const userExists = User.findOne({ username })
    if (userExists) throw new Error('El usuario ya existe')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, 10)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('El usuario no existe')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Contraseña inválida')

    const { password: _, ...publicUser } = user
    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('El username debe ser una cadena de texto')
    if (username.length < 3) throw new Error('El username debe tener al menos 3 caracteres')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('El password debe ser una cadena de texto')
    if (password.length < 6) throw new Error('El password debe tener al menos 6 caracteres')
  }
}
