const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const path = require('path');
const url = require('url');

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('/authorize', (req, response)=>{
	const {client_id} = req.query;
	const client = clients[client_id];
	if(!client){
		response.status(401);
		return response.json({message: 'No client found'});
	}
	const scopes = req.query.scope ? req.query.scope.split(" ") : [];
	if(!(containsAll(client.scopes, scopes))){
		response.status(401);
		return response.json({message: 'Scope are not valid.'});
	}
	
	const requestId = randomString();
	requests[requestId] = req.query;
	response.status(200);
	return response.render('login', {client, scope: req.query.scopes, requestId: requestId});
});

app.post("/approve", (req, res) => {
	const { userName, password, requestId } = req.body
	if (!userName || users[userName] !== password) {
		res.status(401);
		return res.send("Error: user not authorized");
	}
	const clientReq = requests[requestId]
	delete requests[requestId]
	if (!clientReq) {
		res.status(401)
		return res.send("Error: invalid user request");
	}
	const code = randomString()
	authorizationCodes[code] = { clientReq, userName }
	const redirectUri = url.parse(clientReq.redirect_uri)
	redirectUri.query = {
		code,
		state: clientReq.state,
	}
	return res.redirect(url.format(redirectUri))
});

app.post('/token', (req, response) =>{
	const authToken = req.headers.authorization;
	if(!authToken){
		response.status(401);
		return response.json({message: 'Please provide an auth token.'});
	}
	const {clientId, clientSecret} = decodeAuthCredentials(authToken);
	const client = clients[clientId];
	if(!(client && client.clientSecret === clientSecret)){
		response.status(401);
		return response.json({message: 'Unauthorize client'});
	}

	const {code} = req.body;
	const autorizationCode = authorizationCodes[code];
	if(!autorizationCode){
		response.status(401);
		return response.json({message: 'Invalid Authorize code.'});
	}
	delete authorizationCodes[code];
	const signedtoken = jwt.sign(
		{ 
			userName: autorizationCode.userName, 
			scope: autorizationCode.clientReq.scope
		}, 
		config.privateKey,
		{
			algorithm: 'RS256',
		}
	)

	return response.json({token_type: 'Bearer', access_token: signedtoken}).status(200);
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port

	console.log(`Authorize server is running on ${host}:${port}`);
});

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
