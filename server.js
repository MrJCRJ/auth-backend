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
  role: { type: String, default: "user" }, // "user" ou "admin"
});

const User = mongoose.model("User", UserSchema);

// Configuração do Passport para Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // Client ID do Google
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Client Secret do Google
      callbackURL: "http://localhost:5001/auth/google/callback", // URL de callback
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
      { id: req.user._id, email: req.user.email, role: req.user.role }, // Inclua o email aqui
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.redirect(`http://localhost:3000?token=${token}`); // Redirecione para o frontend com o token
  }
);

// Rota de Registro Manual (opcional)
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "Usuário registrado com sucesso!" });
  } catch (err) {
    res.status(500).json({ message: "Erro ao registrar usuário", error: err });
  }
});

// Rota de Login Manual (opcional)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Usuário não encontrado" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Senha incorreta" });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ message: "Erro ao fazer login", error: err });
  }
});

// Inicie o servidor
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Servidor de autenticação rodando na porta ${PORT}`);
});