module.exports = (req, response) => {
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
	if(!authorizationCodes[code]){
		response.status(401);
		return response.json({message: 'Invalid Authorize code.'});
	}
	delete authorizationCodes[code];
}