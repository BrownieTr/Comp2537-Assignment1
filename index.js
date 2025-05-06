/* Set up */
require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 hour (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

/* END secret section */

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false, 
    resave: true
}
));

app.get('/', (req,res) => {
    if (req.session.authenticated) {
        res.send(`
            <p> Hello, ` + req.session.username + `!<br>
            <button onclick=\"window.location.href='/members'\">Go to Members Area</button><br>
            <button onclick=\"window.location.href='/logout'\">Logout</button>
            `);
    } else {
        res.send(`
            <button onclick=\"window.location.href='/signup'\">Signed up</button><br>
            <button onclick=\"window.location.href='/login'\">Login</button>
            `);
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

app.get('/signup', (req, res) => {
    res.send(`
        <p> Create user </p>
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='Name'><br>
            <input name='email' type='text' placeholder='Email'><br>
            <input name='password' type='text' placeholder='Password'><br>
            <button>Submit</button>
        </form>
        `);
})

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!username || !email || !password) {
        let missingFields = [];
      
        if (!username) missingFields.push("Name");
        if (!email) missingFields.push("Email");
        if (!password) missingFields.push("Password");
      
        console.log("Missing fields:", missingFields.join(", "));
      
        res.send(`
          ${missingFields.join(", ")} ${missingFields.length > 1 ? "are" : "is"} required.<br><br>
          <a href="/signup">Try again</a>
        `);
        return;
    }

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(254).required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({username, email, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.send(`
        Invalid name/email/password combination.<br><br>
        <a href="/signup">Try again</a>
        `)
       return;
    }

    const userFound = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    console.log(userFound)

    if (userFound.length != 1) {
        var hashedPassword = await bcrypt.hash(password, saltRounds);
    
        await userCollection.insertOne({username: username, email: email, password: hashedPassword});
        console.log("Inserted user");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect("/members");
        return;
    } else {
        console.log("Email already signed up");
        res.send(`
            Email already signed up<br><br>
            <a href="/signup">Try again</a>
            `)
		return;
    }
})

app.get('/login', (req, res) => {
    res.send(`
        <p> Log in </p>
        <form action='/loginSubmit' method='post'>
            <input name='email' type='text' placeholder='Email'><br>
            <input name='password' type='text' placeholder='Password'><br>
            <button>Submit</button>
            </form>
        `);
})

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    if (!email || !password) {
        let missingFields = [];
      
        if (!email) missingFields.push("Email");
        if (!password) missingFields.push("Password");
      
        console.log("Missing fields:", missingFields.join(", "));
      
        res.send(`
          ${missingFields.join(", ")} ${missingFields.length > 1 ? "are" : "is"} required.<br><br>
          <a href="/login">Try again</a>
        `);
        return;
    }

    const schema = Joi.object(
        {
            email: Joi.string().email().max(254).required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.send(`
        Invalid email/password combination.<br><br>
        <a href="/login">Try again</a>
        `)
       return;
    }

    const userFound = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    console.log(userFound)

    if (userFound.length != 1) {
        console.log("User not found");
        res.send(`
            User password is not registered yet<br><br>
            <a href="/login">Try again</a>
            `)
    } 
    
    if (await bcrypt.compare(password, userFound[0].password)) {
        console.log("Correct password");
        req.session.authenticated = true;
        req.session.username = userFound[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
		console.log("incorrect password");
        res.send(`
            Incorrect password combination.<br><br>
            <a href="/login">Try again</a>
            `)
		return;
    }
})

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        const randomNum = Math.floor(Math.random() * 3);
        res.send(`
            Hello, ` + req.session.username +`.<br><br>
            <img src='/image` + randomNum + `.gif' style='width:250px;'><br>
            <button onclick=\"window.location.href='/logout'\">Logout</button>            
            `);
    } else {
        res.redirect('/');
    }
})

app.use(express.static(__dirname + "/public"))

app.get("*", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port "+port);
})

