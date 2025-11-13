const express = require('express')
const mysql = require('mysql2/promise')
const crypto = require('crypto')
const session = require('express-session')

const conn = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "escola"
})

const app = express()
const PORT = 3001

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(session({
    secret: 'aee0aac0fbc8ee8170795704c99bfbf2ffb8d9a351eef9a2db39a80cd0b65e48',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 600000 }
}))

app.use(express.static('frontend'));

app.get("/", (req, res) => {
    if (req.session.usuario) {
        res.sendFile(__dirname + '/frontend/index.html');
    } else {
        res.redirect('/login');
    }
})

app.get('/login', (req, res) => {
    if (req.session.usuario) {
        return res.redirect('/');
    }
    res.sendFile(__dirname + '/frontend/login.html');
});

app.post("/login", async (req, res) => {
    const { usuario, senha } = req.body

    if (!usuario || !senha) {
        return res.status(400).send('usuário e senha são obrigatórios.');
    }

    const senha_hash = crypto.createHash("sha256").update(senha, "utf-8").digest("hex")

    const sql = "select nome_usuario from usuarios_login where nome_usuario = ? and senha_hash = ?;"

    const ip_usuario = req.ip

    try {
        const [rows] = await conn.query(sql, [usuario, senha_hash])

        const logSql = `INSERT INTO log (data_hora, sql_executado, ip_usuario, parametros, resultado)
                         VALUES (utc_timestamp(), ?, ?, ?, ?)`
        const parametros = JSON.stringify({ usuario, senha_hash })
        const resultado = rows.length > 0 ? 'y' : 'n'
       
        await conn.query(logSql, [sql, ip_usuario, parametros, resultado])

        if (rows.length > 0) {
            req.session.usuario = rows[0].nome_usuario;
            res.redirect('/');
        } else {
            res.send('usuário ou senha inválidos. <a href="/login">tente novamente</a>');
        }

    } catch (error) {
        console.error('erro ao processar login:', error)
        res.status(500).json({
            msg: "erro interno do servidor"
        })
    }
})

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('erro ao encerrar a sessão:', err);
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('erro ao encerrar a sessão:', err);
            return res.status(500).send('Erro ao encerrar a sessão.');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.post('/usuarios', async (req, res) => {
    const { usuario, senha } = req.body;

    if (!usuario || !senha) {
        return res.status(400).send('Usuário e senha são obrigatórios.');
    }

    const senha_hash = crypto.createHash('sha256').update(senha, 'utf-8').digest('hex');
    const sql = 'INSERT INTO usuarios_login (nome_usuario, senha_hash) VALUES (?, ?)';

    try {
        await conn.query(sql, [usuario, senha_hash]);
        res.status(201).send('Usuário cadastrado com sucesso!');
    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
    }
});

app.listen(PORT, () => console.log(`servidor rodando em http://localhost:${PORT}`))


