module.exports = (req, response) =>{
	const {userName, password, requestID} = req.body;
	const {redirect_uri, state} = req.query;
	const userPass = users[userName];
	if(!(userPass && userPass === password)){
		response.status(401);
		return response.json({message: 'Not a valid user.'});
	}
	const request = requests[requestID]; 
	if(!(request)){
		response.status(401);
		return response.json({message: 'RequestID is not valid.'});
	}
	const requestID = randomString();
	authorizationCodes[requestID] = {
		clientReq: req, 
		userName, 
	}
	return response.redirect(`${redirect_uri}?code=${requestID}&state=${state}`);
};
