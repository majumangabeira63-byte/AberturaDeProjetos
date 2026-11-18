
"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const emailsPermitidos = new Set([
  "maria.oliveira@psvsolutions.com.br",
  "joao.tavares@psvsolutions.com.br",
  "ryan.campos@psvsolutions.com.br",
  "enzo.carvalho@psvsolutions.com.br",
  "leonardo.souza@psvsolutions.com.br"
]);

const SESSION_SECRET = process.env.SESSION_SECRET;
const PASSWORD_HASH = process.env.PORTAL_PASSWORD_HASH;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    "Configure SESSION_SECRET com pelo menos 32 caracteres no Railway."
  );
}

if (
  !PASSWORD_HASH ||
  !/^\$2[aby]\$\d{2}\$/.test(PASSWORD_HASH)
) {
  throw new Error(
    "Configure PORTAL_PASSWORD_HASH com um hash bcrypt válido no Railway."
  );
}

const cookieOptions = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  path: "/"
};

function usuarioAtual(req) {
  try {
    const token = req.cookies.psv_session;

    if (!token) return null;

    const dados = jwt.verify(token, SESSION_SECRET, {
      algorithms: ["HS256"]
    });

    if (
      typeof dados.email !== "string" ||
      !emailsPermitidos.has(dados.email)
    ) {
      return null;
    }

    return dados.email;
  } catch {
    return null;
  }
}

function exigirLogin(req, res, next) {
  const email = usuarioAtual(req);

  if (!email) {
    return res.redirect(303, "/login");
  }

  req.usuarioEmail = email;
  next();
}

function enviarHTML(res, nomeArquivo) {
  const arquivo = path.join(__dirname, nomeArquivo);

  fs.stat(arquivo, (erro, dados) => {
    if (erro || !dados.isFile()) {
      console.error("Arquivo não encontrado:", nomeArquivo);

      return res.status(500).send(
        "Erro: arquivo HTML não encontrado no servidor."
      );
    }

    if (dados.size === 0) {
      console.error("Arquivo HTML vazio:", nomeArquivo);

      return res.status(500).send(
        "Erro: o arquivo HTML está vazio no servidor."
      );
    }

    res.set("Cache-Control", "no-store");

    res.sendFile(arquivo, erroEnvio => {
      if (erroEnvio) {
        console.error(
          "Erro ao enviar arquivo:",
          nomeArquivo,
          erroEnvio.message
        );

        if (!res.headersSent) {
          res.status(500).send(
            "Erro ao carregar a página."
          );
        }
      }
    });
  });
}

// Tela de login
app.get("/login", (req, res) => {
  if (usuarioAtual(req)) {
    return res.redirect(303, "/");
  }

  enviarHTML(res, "login.html");
});

// Limite de tentativas
const limitarLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// Autenticação
app.post("/api/login", limitarLogin, async (req, res) => {
  try {
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    const senha =
      typeof req.body?.senha === "string"
        ? req.body.senha
        : "";

    if (!email || !senha) {
      return res.status(401).json({
        error: "E-mail ou senha inválidos."
      });
    }

    const senhaValida = await bcrypt.compare(
      senha,
      PASSWORD_HASH
    );

    if (
      !emailsPermitidos.has(email) ||
      !senhaValida
    ) {
      return res.status(401).json({
        error: "E-mail ou senha inválidos."
      });
    }

    const token = jwt.sign(
      { email },
      SESSION_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "8h"
      }
    );

    res.cookie("psv_session", token, {
      ...cookieOptions,
      maxAge: 8 * 60 * 60 * 1000
    });

    res.set("Cache-Control", "no-store");
    return res.json({ ok: true });

  } catch (erro) {
    console.error("Erro de autenticação:", erro.message);

    return res.status(500).json({
      error: "Erro interno na autenticação."
    });
  }
});

// Usuário conectado
app.get("/api/me", (req, res) => {
  const email = usuarioAtual(req);

  res.set("Cache-Control", "no-store");

  if (!email) {
    return res.status(401).json({
      error: "Não autorizado."
    });
  }

  return res.json({ email });
});

// Sair
app.post("/api/logout", (req, res) => {
  res.clearCookie("psv_session", cookieOptions);

  res.set("Cache-Control", "no-store");
  return res.json({ ok: true });
});

// Logo
app.get("/logo.png", (req, res) => {
  res.sendFile(
    path.join(__dirname, "logo.png"),
    erro => {
      if (erro && !res.headersSent) {
        res.status(404).end();
      }
    }
  );
});

// Dashboard protegido
app.get("/", exigirLogin, (req, res) => {
  enviarHTML(res, "index.html");
});

// Rotas não encontradas
app.use((req, res) => {
  res.status(404).send("Página não encontrada.");
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Portal PSV iniciado na porta", PORT);
  console.log(
    "login.html:",
    fs.existsSync(path.join(__dirname, "login.html"))
  );
  console.log(
    "index.html:",
    fs.existsSync(path.join(__dirname, "index.html"))
  );
});
