const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// Configuração da sessão
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Chave secreta para a sessão
    resave: false,
    saveUninitialized: true,
  })
);

// Inicialize o Passport
app.use(passport.initialize());
app.use(passport.session());

// Conecte ao MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Modelo de Usuário
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String }, // ID do Google
  name: { type: String }, // Nome do usuário
  role: { type: String, default: "user" }, // "user" ou "admin"
});

const User = mongoose.model("User", UserSchema);

// Configuração do Passport para Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://auth-backend-jose-ciceros-projects.vercel.app/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Verifique se o usuário já está registrado
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          // Crie um novo usuário se não existir
          user = new User({
            googleId: profile.id,
            email: profile.emails[0].value, // Email do Google
            name: profile.displayName, // Nome do Google
          });
          await user.save();
        }

        return done(null, user); // Retorna o usuário
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// Serialize e deserialize o usuário
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Rota de Registro com Google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Callback do Google OAuth
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Gere um token JWT para o usuário
    const token = jwt.sign(
      {
        id: req.user._id,
        email: req.user.email,
        name: req.user.name, // Inclua o nome aqui
        role: req.user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.redirect(`https://my-history-frontend-git-main-jose-ciceros-projects.vercel.app?token=${token}`); // Redirecione para o frontend com o token
  }
);

// Inicie o servidor
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Servidor de autenticação rodando na porta ${PORT}`);
});