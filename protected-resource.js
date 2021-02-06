const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils");
const jwt = require("jsonwebtoken");
const { verify } = require('sinon');
const { response } = require('express');

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/user-info', (req, res) =>{
	const authorization = req.headers.authorization;
	if(!authorization){
		return res.status(401).send("Not found any token to varify.");
	}
	const token = authorization.slice(7);
	try{
		const info =  jwt.verify(token, config.publicKey, {algorithms: ['RS256']}, );
		const userData = users[info.userName];
		const scope = info.scope.split(" ");
		const backData = {};
		for(let i =0; i<scope.length; i++){
			const singleValue = scope[i].slice(11);
			backData[singleValue] = userData[singleValue];
		}
		return res.status(200).json(backData);
	} catch(err){
		return res.status(401).send(err);
	}
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log(`Protected Resource server is running on http://${host}:${port}`);
})

// for testing purposes
module.exports = {
	app,
	server,
}
