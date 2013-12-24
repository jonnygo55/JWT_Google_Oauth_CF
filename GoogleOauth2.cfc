component displayname="GoogleOauth2" output="false"
{
	variables.my.p12FileLocation = ""; //your p12 file location goes here
	variables.my.emailOfServiceAccount = ''; //the email address listed on Google Developer's console for your project and service account goes here (https://cloud.google.com/console?redirected=true#/project)
	variables.my.scopesForToken = ''; //list of services to authorize token for (i.e. https://www.googleapis.com/auth/admin.directory.user) 
	variables.my.emailOfSuperAccount = ''; //email of super account...seemingly needed for the scope I was was requesting...
	variables.my.googleOauthURL = 'https://accounts.google.com/o/oauth2/token';

	public GoogleOauth2 function init () {
		if (structKeyExists(arguments,'p12FileLocation')){
			variables.my.p12FileLocation = arguments.p12FileLocation;
		}
		if (structKeyExists(arguments,'emailOfServiceAccount')){
			variables.my.emailOfServiceAccount = arguments.emailOfServiceAccount;
		}
		if (structKeyExists(arguments,'emailOfSuperAccount')){
			variables.my.emailOfSuperAccount = arguments.emailOfSuperAccount;
		}
		if (structKeyExists(arguments,'p12FileLocation')){
			variables.my.p12FileLocation = arguments.p12FileLocation;
		}
		return this;
	}

	public struct function getToken() {
		
		if (structKeyExists(arguments,'scopesForToken')){
			variables.my.scopesForToken = arguments.scopesForToken
		}
		
		//create the JWT Packet
		local.JWTPacket = getJWTPacket();

		//send it to Google
		local.result = sendPacket(JWT=local.JWTPacket);;

		try {
			//set the return token to a variable
			local.returnJson = DeserializeJSON(result.fileContent.toString());
			local.token = returnJson.access_token;
			local.returnPkg = {"token"=local.token,"success"=true};
		}
		catch(any e) {
			local.returnPkg = {"success"=false};
		}

		return local.returnPkg;
	}

	private struct function sendPacket(required string JWT ) {
		/* get token from Google */
		local.httpService = new http();
		local.httpService.setMethod("post");
		local.httpService.setCharset("utf-8");
		local.httpService.setUrl("#variables.my.googleOauthURL#");
		local.httpService.addParam(type="header",name="Content-Type",value="application/x-www-form-urlencoded");
		local.httpService.addParam(type="formfield",name="grant_type",value="urn:ietf:params:oauth:grant-type:jwt-bearer");
		local.httpService.addParam(type="formfield",name="assertion",value="#arguments.jwt#");
		local.result = httpService.send().getPrefix();

		return local.result;

	}

	private string function getJWTPacket() {
		//first create the header hard code the base64 value since there is only one
		// same as {"alg":"RS256","typ":"JWT"} in base64
		 local.jwtHeader = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';
		 //use epoch time and one hour more for duration of token...exp could be dynamic under 60 minutes
		 local.epoch = dateDiff('s', dateConvert('utc2Local', createDateTime(1970, 1, 1, 0, 0, 0)), now());
		 local.exp = dateDiff('s', dateConvert('utc2Local', createDateTime(1970, 1, 1, 0, 0, 0)), dateAdd('n',60,now()));

		 //claim set includes email from developers console, scope which is service you want to access, and authorization time up to one hour
		 local.jwtClaimSet = serializeJSON({
		   "iss"=variables.my.emailOfServiceAccount,
		   "scope"=variables.my.scopesForToken,
		   "aud"=variables.my.googleOauthURL,
		   "exp"=local.exp,
		   "iat"=local.epoch,
		   "sub"=variables.my.emailOfSuperAccount
		});
		// base 64 and url encode it
		local.jwtClaimSet = Base64URLEncode(jwtClaimSet);
		// combine header and claim set to be signed
		local.signString = '#jwtHeader#.#jwtClaimSet#';

		//sign it
		local.signedString = signTheString(String=local.signString);
		//encode it
		local.encodedSignedString = Base64URLEncode(String=toString(local.signedString));

		//you now have enough to send full jwt to google to get a token back
		local.jwt = '#local.jwtHeader#.#local.jwtClaimSet#.#local.encodedSignedString#';

		return local.jwt;
	}

	private array function signTheString(required string String ) {
		//get the certificate (p12) and extract the privateKey
		// create input file stream from certificate
		local.fileStream = CreateObject( "java", "java.io.FileInputStream" ).init( variables.my.p12FileLocation );
		local.keystore = CreateObject( "java", "java.security.KeyStore" ).getInstance("PKCS12");
		//password from google never changes...hard coded for now
		local.password = "notasecret";
		local.keystore.load(fileStream, password.toCharArray());
		local.key = local.keystore.getKey("privatekey", password.toCharArray());
		//now you've got the key
		local.privateKey = local.key.getEncoded();

		//use it to sign the header and claimset
		local.signature = createObject("java", "java.security.Signature");
		local.keyFactory = createObject("java","java.security.KeyFactory");
		local.keySpec = createObject("java","java.security.spec.PKCS8EncodedKeySpec");

		local.signature = signature.getInstance("SHA256withRSA");
		local.signature.initSign(keyFactory.getInstance("RSA").generatePrivate(keySpec.init(local.privateKey)));
		local.jMsg = JavaCast("string",arguments.String).getBytes('utf-8');
		local.signature.update(local.jMsg);
		local.signBytes = local.signature.sign();

		return local.signBytes;
	}


	private string function Base64URLEncode(required string String ){
		return Replace( Replace( Replace( toBase64(Arguments.String), "=", "", "all"), "+", "-", "all"), "/", "_", "all");
	}

}
