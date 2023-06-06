/**
 * JWT Utils Helper Function
 * 
 * Requirement:
 * importMappingRule("standardUtils", "loggerUtils"); 
 */

/**
 * Issue JSON Web Tokens (JWT)
 */
var token = new function () {
    this.issue = function (claims, RS256) {
        logger.log(VERBOSE, "token.issue() claims: " + JSON.stringify(claims))
        logger.log(VERBOSE, "token.issue() RS56: " + JSON.stringify(RS256))

        tokenStsuu = new STSUniversalUser();
        // Define signing certificate for JWT.
        tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("signing.db", "", "" + RS256.keystore));
        tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("signing.cert", "", "" + RS256.key));
        tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("signing.alg", "", "RS256"));
        if (RS256.kid != undefined) {
            tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("signing.kid", "", "" + RS256.kid));
        }
        // Add claims to STSUU.
        tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("claim_json", "", "" + JSON.stringify(claims)));
        // Issue JWT token.
        stsToken = this.callSts(tokenStsuu.toXML().getDocumentElement(), "urn:jwt:issue", "urn:jwt:issue");
    
        if (stsToken.token) {
            return stsToken.token.getTextContent();
        } else {
            logger.log(FAILED, "Error getting token from STS: " + stsToken.errorMessage);
        }
    }
    
    this.callSts = function (baseToken, appliesToAddress, issuerAddress) {
        tokenResult = LocalSTSClient.doRequest("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue", appliesToAddress, issuerAddress, baseToken, null);
        return tokenResult;
    }
};