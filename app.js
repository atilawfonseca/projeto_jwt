require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('./models/User')

const app = express();

//Config JSON response
app.use(express.json())
//como as respostas são em json, tem que habilitar para aceitar respostas em json com app.use(express.json())

//login usuario
app.post("/auth/login", async (req, res) => {
    const {email, password} = req.body; 
    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    //validacoes
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }

    const user = await User.findOne({email:email});

    if(!user) {
        return res.status(404).json({msg: 'Este usuário não existe'})
    }
    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({msg: 'Senha inválida'})
    }

    try {
        const secret = process.env.SECRET; 

        const token = jwt.sign({
            id: user._id, 
        }, secret,)

        res.status(200).json({msg:"Autenticação correta", token})
    } catch (error) {
        res.status(500).json({
            msg: "Aconteceu um erro no servidor!"
        })
    }

})

//Registrar Usuário
app.post('/auth/register', async (req, res) => {
    const {name, email, password, confirpassword} = req.body

    //validacoes
    if(!name) {
        return res.status(422).json({msg: 'O nome é obrigatório!'})
    }
    //validacoes
    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório!'})
    }
    //validacoes
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória!'})
    }
    if(password != confirpassword) {
        return res.status(422).json({msg: 'As senhas não são as mesmas!'})
    }

    //checar se usario existe
    const UserExists = await User.findOne({email:email});

    if(UserExists) {
        return res.status(422).json({msg: 'Por favor, utilize outro email'})
    }

    //create senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    //criar usuario
    const user = new User({
        name, 
        email, 
        password:passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({msg:"Usuário criado com sucesso"})
    }catch(error) {
        res.status(500).json({msg: error})
    }
    
})

const dbUser = process.env.DB_USER; 
const dbPass = process.env.DB_PASS;
//ROTA PUBLICA
app.get('/', (req, res) => {
    res.status(200).json({msg: "bem vindo a nossa API"})
})

//ROTA PRIVADA
app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id; 

    //check if user exists
    const user = await User.findById(id, '-password');
    if(!user) {
        res.status(404).json({msg:"usuário não encontrado"})
    }
    res.status(200).json({user})
    
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: "acesso negado!"})
    }

    try {

        const secret = process.env.SECRET; 
        jwt.verify(token, secret);
        next()
        
    } catch (error) {
        res.status(400).json({msg: "Token invalido"})
    }
}

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.brvcgx7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(()=> {
    app.listen(3000);
    console.log("Conectou ao BD")
}).catch((erro) => console.log(erro))


