/**
 * RP Utils.js
 * Used by RP's leveraging an OpenID provider (OP).
 * 
 * Basic use:
 * 
 * importMappingRule("standardUtils", "loggerUtils", "jwtUtils", "rpUtils");
 * 
 * var request = Object.create(IdentityUser);
 * request.acr = IP1
 * request.scope += " public_profile"
 * request.addRequestParameters.prompt()
 * request.authorizeRequest()
 * 
 * Requirements:
 * importMappingRule("standardUtils", "loggerUtils", "jwtUtils");
 */

const IDP_TOKEN_LIFETIME = 300; // 5 minutes
const NOT_BEFORE = 300; // 5 minutes

/**
 * Check whether an object is empty.
 * @param {object} obj JSON object.
 * @return {boolean} Returns `true` if object is empty, else returns `false`.
 */
function isObjectEmpty(obj) {
    return JSON.stringify(obj) === '{}'
}

const IP1 = ["urn:acr:ip1", "urn:acr:ip2", "urn:acr:ip3"];
const IP2 = ["urn:acr:ip2", "urn:acr:3"];
const IP3 = ["urn:acr:ip3"];

const MIN_IP1 = /urn\:acr\:ip[1-3]/;
const MIN_IP2 = /urn\:acr\:ip[2-3]/;
const MIN_IP3 = /urn\:acr\:ip[3-3]/;

const ACR_LEVELS = {
    IP1: "MIN_IP1",
    IP2: "MIN_IP2",
    IP3: "MIN_IP3"
}

const MIN_LEVELS = {
    "MIN_IP1": MIN_IP1,
    "MIN_IP2": MIN_IP2,
    "MIN_IP3": MIN_IP3,
}

const IdentityUser = {
    scope: "openid email",
    acr: [],
    min_acr: "",
    nonce: "",
    state: "",
    login_hint: "",
    claims: {
        id_token: {},
        userinfo: {}
    },
    user: {
        pairwiseId: "",
        acr: "",
        given_name: "",
        family_name: "",
        birthdate: "",
        email: "",
        email_verified: "",
        id_token: "",
        access_token: ""
    },

    addRequestParameters: {
        /**
         * Space delimited, string values that specifies whether the end-user needs to reauthenticate.
         * @param {('login'|'none')} prompt OIDC prompt value. Default: `login`.
         */
        prompt: function (prompt) {
            promptString = prompt ? prompt : "login";
            stsuu.addContextAttribute(new Attribute("prompt", "urn:ibm:SAM:oidc:rp:authorize:req:param", promptString));
        },
        /**
         * Email login hint identifier the end-user MUST use to log in. Not authenticating with this email will result in an error.
         * @param {string} email Email login hint.
         */
        loginHint: function (email) {
            // Validate email provided.
            IdentityUser.login_hint = inputValidate.email(email) ? email : "";
            stsuu.addContextAttribute(new Attribute("login_hint", "urn:ibm:SAM:oidc:rp:authorize:req:param", IdentityUser.login_hint));
            IDMappingExtUtils.setSPSSessionData("identity_login_hint", IdentityUser.login_hint);
        }
    },

    /**
     * Build the `/authorise` URL.
     */
    authorizeRequest: function () {
        // Setup initial logging.
        logger.doingOidcAdvanced();
        logger.partner = "" + (stsuu.getContextAttributes().getAttributeByNameAndType("client_id", "urn:ibm:SAM:oidc:rp:authorize:req:param")).getValues()[0];

        // Set scopes.
        stsuu.getContextAttributes().removeAttributeByNameAndType("scope", "urn:ibm:SAM:oidc:rp:authorize:req:param");
        stsuu.getContextAttributes().setAttribute(new Attribute("scope", "urn:ibm:SAM:oidc:rp:authorize:req:param", this.scope));

        // Set nonce value.
        this.nonce = "" + java.util.UUID.randomUUID();
        stsuu.addContextAttribute(new Attribute("nonce", "urn:ibm:SAM:oidc:rp:authorize:req:param", this.nonce));
        IDMappingExtUtils.setSPSSessionData("identity_nonce", this.nonce);

        // Set state value.
        this.state = "" + java.util.UUID.randomUUID();
        logger.state = this.state;
        stsuu.addContextAttribute(new Attribute("state", "urn:ibm:SAM:oidc:rp:authorize:req:param", this.state));

        // Delete 'claims.userinfo' if object is empty.
        if (isObjectEmpty(this.claims.userinfo)) {
            delete this.claims.userinfo;
        }

        // Check if ACR is defined.
        if (this.acr[0]) {
            // Add the claims object to the request.
            this.claims.id_token.acr = { "essential": true, "values": this.acr };
            stsuu.addContextAttribute(new Attribute("claims", "urn:ibm:SAM:oidc:rp:authorize:req:param", JSON.stringify(this.claims)));
    
            // Set minimum ACR value to be returned.
            this.min_acr = ACR_LEVELS[this.acr];
            IDMappingExtUtils.setSPSSessionData("identity_min_acr", this.min_acr);
        }
    },

    /**
     * Build the `/token` URL.
     * @param {object} keystore RS256 object key store to use to sign the JWT.
     */
    tokenRequest: function (keystore) {
        clientId = getAttributeValue('client_id', 'urn:ibm:SAM:oidc:rp:meta', CONTEXT, "");
        tokenUrl = getAttributeValue('token_url', 'urn:ibm:SAM:oidc:rp:meta', CONTEXT, "");
        this.state = "" + stsuu.getContextAttributes().getAttributeValueByName("state");

        // Setup initial logging.
        logger.doingOidcAdvanced();
        logger.state = this.state;
        logger.partner = clientId;

        now = new Date();
        claims = {};
        claims.iat = Math.floor(now.getTime() / 1000);
        claims.exp = Math.floor((now.getTime() + (1 * IDP_TOKEN_LIFETIME * 1000)) / 1000);
        claims.nbf = Math.floor(now.getTime() / 1000 - NOT_BEFORE);
        claims.sub = clientId;
        claims.jti = "" + java.util.UUID.randomUUID();
        claims.iss = clientId;
        claims.aud = tokenUrl;

        idpToken = token.issue(claims, keystore);
        if (idpToken) {
            stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("client_assertion", "urn:ibm:SAM:oidc:rp:token:req:param", idpToken));
            stsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("client_assertion_type", "urn:ibm:SAM:oidc:rp:token:req:param", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            logger.log(VERBOSE, "JWT created. value: " + idpToken)
        } else {
            logger.log(ERROR, "Failure to create JWT")
        }
    },

    /**
     * Validate the response attributes from the OP and set-up the `user` object.
     */
    login: function () {
        this.user.id_token = getAttributeValue('id_token', 'urn:ibm:SAM:oidc:rp:token:rsp:param', CONTEXT, '');
        this.user.pairwiseId = getAttributeValue('sub', 'urn:id_token:attribute:token', ATTRIBUTE, '');
        this.user.acr = getAttributeValue('acr', 'urn:id_token:attribute:token', ATTRIBUTE, '');
        this.user.given_name = getAttributeValue('given_name', 'urn:ibm:SAM:oidc:rp:userinfo:rsp:param', ATTRIBUTE, '');
        this.user.family_name = getAttributeValue('family_name', 'urn:ibm:SAM:oidc:rp:userinfo:rsp:param', ATTRIBUTE, '');
        this.user.birthdate = getAttributeValue('birthdate', 'urn:ibm:SAM:oidc:rp:userinfo:rsp:param', ATTRIBUTE, '');
        this.user.email = getAttributeValue('email', 'urn:ibm:SAM:oidc:rp:userinfo:rsp:param', ATTRIBUTE, '');
        this.user.email_verified = getAttributeValue('email_verified', 'urn:ibm:SAM:oidc:rp:userinfo:rsp:param', ATTRIBUTE, '');
        this.min_acr = IDMappingExtUtils.removeSPSSessionData("identity_min_acr") || "MIN_IP4"; // Default to highest level.

        // Setup initial logging.
        logger.doingOidcRp();
        logger.partner = getAttributeValue('aud', 'urn:id_token:attribute:token', ATTRIBUTE, '');
        logger.partnerId = this.user.pairwiseId

        // Validate the ACR returned exceeds the one requested.
        if (!(this.user.acr).match(MIN_LEVELS[this.min_acr])) {
            logger.log(FAILED, "ACR value returned does not meet requirements: " + this.user.acr + ". Required: " + this.min_acr);
            // TODO: Error handling.
        };

        // Validate the 'nonce' returned, matches the one sent in the '/authorise' request.
        this.nonce = IDMappingExtUtils.removeSPSSessionData("identity_nonce") || "";
        if (this.nonce != this.user.nonce) {
            logger.log(FAILED, "Nonce returned does not equal nonce sent: " + this.user.nonce + ". Required: " + this.nonce);
            // TODO: Error handling.
        }

        // If an email 'login_hint' was sent, validate it against the email returned.
        this.login_hint = IDMappingExtUtils.removeSPSSessionData("identity_login_hint") || "";
        if (this.login_hint) {
            if (this.login_hint != this.user.email) {
                logger.log(FAILED, "Email returned is not equal to the email login hint sent: " + this.user.email + ". Required: " + this.login_hint);
                // TODO: Error handling.
            }
        }
    }
}
