const express = require("express")
const bodyParser = require("body-parser")
const axios = require("axios").default
const { randomString, timeout } = require("./utils");
const url = require('url');

const config = {
	port: 9000,

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
	userInfoEndpoint: "http://localhost:9002/user-info",
}
let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/client")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get('authorize', (req, res) =>{
	state = randomString();
	const redirectURL = url.parse(config.authorizationEndpoint);
	redirectURL.query = {
		response_type: 'code',
		client_id: config.clientId,
		redirect_uri: config.redirectUri,
		scope: "permission:name permission:date_of_birth",
		state,
	};

	return res.redirect(url.format(redirectURL));
});


app.get('callback', (req, res) =>{
	if(!(state === req.query.state)){
		return res.status(403).send('Forbidden');
	}
	axios({
		method: 'POST',
		url: config.tokenEndpoint,
		auth: {
			username: config.clientId,
			password: config.clientSecret,
		},
		data: {
			code: req.query.code,
		}
	}).then(
		response =>{
			axios({
				method: 'GET',
				url: config.userInfoEndpoint,
				headers: {
					authorization: `bearer ${response.access_token}`,
				}
			}).then(userInfo =>{
				return res.render('welcome', userInfo.data);
			}).catch(userInfoErr =>{
				return res.status(401).send(userInfoErr);
			});
		}
	).catch(err =>{
		return res.status(401).send(err);
	});
});


const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address;
	var port = server.address().port;
	console.log(`Client is running on http://${host}:${port}`);
})

// for testing purposes

module.exports = {
	app,
	server,
	getState() {
		return state
	},
	setState(s) {
		state = s
	},
}
