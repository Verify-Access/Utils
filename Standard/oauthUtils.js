/**
 * OAuth Utils Helper Function
 * Used in the Pre/Post token mapping rules.
 * 
 * Requirement:
 * importMappingRule("standardUtils", "loggerUtils"); 
 */

/**
 * OAuth functions
 */
var oauth = new function () {
    /**
     * Updates the `scope` key value in the `oauth20/token` response.
     * @param {object} userClaims 
     */
    this.updateScopes = function (userClaims) {
        tempAttr = stsuu.getContextAttributes().getAttributeValuesByNameAndType("scope", "urn:ibm:names:ITFIM:oauth:query:param");
        if (tempAttr != null && tempAttr.length > 0) {
            let newScopes = [];
            newScopes.push('openid');
    
            if (userClaims) {
                if (userClaims.given_name || userClaims.family_name || userClaims.birthdate) { newScopes.push('profile') };
                if (userClaims.email) { newScopes.push('email') };
                if (userClaims.phone_number) { newScopes.push('phone') };
            }
    
            stsuu.getContextAttributes().removeAttributeByNameAndType("scope", "urn:ibm:names:ITFIM:oauth:query:param");
            stsuu.getContextAttributes().setAttribute("scope", "urn:ibm:names:ITFIM:oauth:query:param", jsToJavaArray(newScopes));
        }
    }

    /**
     * Reads the code from the STSUU.
     * @returns The `stateId`
     */
    this.getStateInPreTokenRule = function () {
        var token = getAttributeValue("code", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, null) || getAttributeValue("refresh_token", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, null)

        // Uses the token to get the token object from the database.
        if (token != null) {
            grant = OAuthMappingExtUtils.getToken(token);
            if (grant != null) {
                return "" + grant.getStateId();
            }
        }
    }

    /**
     * Validate algorithm RP used to sign client assertion.
     * @param {array} supportedAlg Array of supported algorithms, e.g. ["RS256", "ES256"]
     */
    this.validateJwtAlgorithm = function (supportedAlg) {
        clientAssertionHeader = JSON.parse(getAttributeValue("header", "urn:ibm:names:ITFIM:oauth:jwt:param:urn:com:ibm:JWT", ATTRIBUTE, "{}")); // Example: {"kid":"d0zvbjSa2MR","alg":"RS256"}
        if (supportedAlg.indexOf(clientAssertionHeader.alg) == -1) {
            logger.log(ERROR, "JWT alg is not RS256: JWT Header: " + JSON.stringify(clientAssertionHeader));
            OAuthMappingExtUtils.throwSTSCustomUserMessageException("JWT alg is not supported", 401, "access_denied");
        }
    }

    /**
     * Check `exp` is NOT unreasonably far into the future.
     * @param {number} maxTime Time in minutes. Default 120 minutes.
     */
    this.validateJwtExpiry = function (maxTime) {
        minutes = maxTime ? maxTime : 120
        expiry = getAttributeValue("exp", "urn:com:ibm:JWT:claim", ATTRIBUTE, null);
        notBeyond = Math.floor((new Date().getTime() + (minutes * 60 * 1000)) / 1000) // 120 minutes
        if (expiry > notBeyond) {
            logger.log(ERROR, "Expiry of JWT unreasonably far in the future: JWT Expiry: " + new Date(expiry * 1000) + ". Not beyond: " + new Date(notBeyond * 1000));
            OAuthMappingExtUtils.throwSTSCustomUserMessageException("Expiry claim value unreasonably far in the future", 400, "invalid_request");
        }
    }

    /**
     * Check `jti` is unique and not replayed.
     */
    this.validateUniqueJti = function () {
        jti = getAttributeValue("jti", "urn:com:ibm:JWT:claim", ATTRIBUTE, null);
        if (IDMappingExtUtils.getIDMappingExtCache().exists(jti)) {
            OAuthMappingExtUtils.throwSTSCustomUserMessageException("JWT ID claim value not unique", 400, "invalid_request");
        } else {
            // Storing `jti` claim in DMAP.
            expiry = getAttributeValue("exp", "urn:com:ibm:JWT:claim", ATTRIBUTE, null);
            IDMappingExtUtils.getIDMappingExtCache().put(jti, "client_assertion", (expiry * 1)); // Expiry of `client_assertion`.
        }
    }

    this.enforcePrivateKeyJwt = function () {
        client_assertion = getAttributeValue("client_assertion", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, null);
        client_assertion_type = getAttributeValue("client_assertion_type", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, "");
        if (!client_assertion || client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
            logger.log(ERROR, "Missing client_assertion or client_assertion_type from RP request. client_assertion_type: " + client_assertion_type + "client_assertion: " + client_assertion)
            OAuthMappingExtUtils.throwSTSCustomUserMessageException("Must be JWT-Bearer", 400, "invalid_request");
        }
    }
}