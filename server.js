const express = require('express')

const mysql = require('mysql2/promise')

const crypto = require('crypto')



const conn = mysql.createPool({ 

    host:"localhost",

    user:"root",

    password: "",

    database: "escola"

})



const app = express()

app.use(express.json())



const PORT = 3001

app.listen(PORT)



app.get("/", (req, res) => { 

    res.json({

        rotas: {

            "/":"GET- Obtém todas as rotas disponíveis", 

            "/login":"POST - Recebe usuario para autenticar"

        }

    })

})



app.post("/login", async (req, res) => {

    const {usuario, senha} = req.body 

    const senha_hash = crypto.createHash("sha256").update(senha,"utf-8").digest("hex")



    const sql = "select * from usuarios_login where nome_usuario = ? and senha_hash = ?;";



    

    const ip_usuario = req.ip 



    try {

     

        const [rows] = await conn.query(sql, [usuario, senha_hash]) 



        

        const logSql = `INSERT INTO log (data_hora, sql_executado, ip_usuario, parametros, resultado)

                        VALUES (UTC_TIMESTAMP(), ?, ?, ?, ?)`  



        const parametros = JSON.stringify({ usuario, senha_hash }) 



        const resultado = rows.length > 0 ? 'Y' : 'N' 

        await conn.query(logSql, [sql, ip_usuario, parametros, resultado]) 





        if(rows.length > 0){

            res.json({

                Msg: "Existe", usuario: rows[0]

            })



        } else {

            res.json({ 

                Msg: "Usuario ou senha incorreta"

            })

        }





    } catch (error) {

        console.error('Erro ao processar login:', error)

        res.status(500).json({

            Msg: "Erro interno do servidor"

        })

    }





})