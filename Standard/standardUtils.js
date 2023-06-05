/**
 * Standard Utils Helper function
 */

// Standard Imports.
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);
importClass(Packages.com.ibm.security.access.server_connections.ServerConnectionFactory);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.java.lang.System);

const CONTEXT = 'context';
const ATTRIBUTE = 'attribute';
const REQUEST = 'request';

/**
 * Retrieves the named attribute from the *default* STSUU and converts to a JS Array full of JS Strings.
 * @param  {String} name        Name of the attribute in the STSUU
 * @param  {String} type        Type of the attribute in the STSUU
 * @param  {String} container   Will be one of "context" | "attribute" | "request"
 * @return {Array}              Array of Strings (or empty in the Null case)
 */
function getAttributeValues(name, type, container) {
    if (container === CONTEXT) {
        values = stsuu.getContextAttributes().getAttributeValuesByNameAndType(name, type);
    } else if (container === ATTRIBUTE) {
        values = stsuu.getAttributeContainer().getAttributeValuesByNameAndType(name, type);
    } else if (container === REQUEST) {
        values = stsuu.getRequestSecurityToken().getAttributeValuesByNameAndType(name, type);
    }

    if (values != null) {
        values = values.map(function (value) {
            // force the JS string conversion
            if (value != null) {
                value = '' + value;
            }
            return value;
        });
    } else {
        values = [];
    }
    return values;
}

/**
 * Gets the attribute from the STSUU (as a String) or returns the default Value.
 * @param  {String} name            Name of the attribute in the STSUU
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @param  {*}      defaultValue    Default Value (any type) to return
 * @return {*}                      String if there is a value, default if not.
 */
function getAttributeValue(name, type, container, defaultValue) {
    var values = getAttributeValues(name, type, container);
    if (values == null || values.length == 0) {
        return defaultValue;
    }
    return values[0];
}

const RST_HEADER = "Header"
const RST_COOKIES = "Cookie"
const RST_ATTRIBUTES = "Attribute"

function getRstClaims(attrType, attrName, defaultValue, wantArray) {
    var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

    for (var i = 0; i < claims.length; i++) {
        var dialect = claims[i].getAttribute("Dialect");

        if ("urn:ibm:names:ITFIM:httprequest".equalsIgnoreCase(dialect)) {
            var attrs = claims[i].getElementsByTagName(attrType);

            for (var j = 0; j < attrs.getLength(); j++) {
                var item = attrs.item(j);
                var name = item.getAttribute("Name");
                var values = item.getElementsByTagName("Value");
                if (name == attrName) {
                    if (values.getLength() == 0) {
                        return defaultValue
                    } else if (!wantArray) {
                        return "" + values.item(0).getTextContent();
                    } else {
                        var returnArray = []
                        for (var k = 0; k < values.getLength(); k++) {
                            returnArray.push("" + values.item(k).getTextContent())
                        }
                        return returnArray;
                    }
                }
            }
        }
    }
}

/**
 * Gets an array of attributes from the STSUU (All that match the same type).
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @return {object}                 Javascript object with JS strings for each key and value.
 */
function getAllAttributes(type, container) {
    if (container === CONTEXT) {
        attrs = stsuu.getContextAttributes().getAttributesByType(type);
    } else if (container === ATTRIBUTE) {
        attrs = stsuu.getAttributeContainer().getAttributesByType(type);
    } else if (container === REQUEST) {
        attrs = stsuu.getRequestSecurityToken().getAttributesByType(type);
    }

    // We have an array of Attributes - which might then individually have an array of attribute values
    if (attrs != null) {
        attrs = attrs.map(function (attr) {
            var ret = {}
            if (attr != null) {
                values = attr.getValues()
                values = values.map(function (value) {
                    if (value != null) {
                        value = value + ""
                    }
                    return value
                })
                // return a string for one, an array for multiple.
                if (values.length == 1) {
                    ret["" + attr.getName()] = values[0]
                } else {
                    ret["" + attr.getName()] = values
                }

            }
            return ret;
        });
    } else {
        attrs = [];
    }
    var allAttrs = {}
    for (k in attrs) {
        Object.assign(allAttrs, attrs[k])
    }

    return allAttrs;
}

/**
 * Gets the Names of all the attributes that match a specific type in the STSUU. Really useful for scopes.
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @return {object}                 Javascript object with JS strings for each key and value.
 */
function getAllAttributeNames(type, container) {
    if (container === CONTEXT) {
        attrs = stsuu.getContextAttributes().getAttributesByType(type);
    } else if (container === ATTRIBUTE) {
        attrs = stsuu.getAttributeContainer().getAttributesByType(type);
    } else if (container === REQUEST) {
        attrs = stsuu.getRequestSecurityToken().getAttributesByType(type);
    }

    // We have an array of Attributes - which might then individually have an array of attribute values
    if (attrs != null) {
        attrs = attrs.map(function (attr) {
            return "" + attr.getName()
        });
    } else {
        attrs = [];
    }

    return attrs;
}

const INFOMAP_PARAM = "urn:ibm:security:asf:request:parameter";
const INFOMAP_ATTRIBUTE = "urn:ibm:security:asf:request:token:attribute";
const INFOMAP_HEADER = "urn:ibm:security:asf:request:header";

function getInfoMapValue(name, type, defaultValue) {
    let tempVal = context.get(Scope.REQUEST, type, name);
    if (tempVal != null && tempVal.length() > 0) {
        return "" + tempVal;
    } else {
        return defaultValue;
    }
}

/**
 * Redirects browser to custom URL from Infomap. Will only work if template script is 
 * @param {string} targetUrl Full redirect URL
 */
function setInfoMapValue(key, value) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", key, value);
}


/**
 * Converts a JS to a Java Array.  Used in OTP and some OIDC cases.  Is originally supplied in OTPGetMethods.js.
 * @param  {Array} jsArray          JS Array to convert
 * @return {*}                      Java Array.
 */
function jsToJavaArray(jsArray) {
    var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
    for (var i = 0; i < jsArray.length; i++) {
        javaArray[i] = jsArray[i];
    }
    return javaArray;
}

/**
 * Converts a Java to a JS Array. 
 * @param  {Array} arr              Java Array to convert
 * @return {*}                      JS Array.
 */
function javaToJsArray(arr) {
    if (arr != null) {
        values = arr.map(function (value) {
            // force the JS string conversion
            if (value != null) {
                value = '' + value;
            }
            return value;
        });
    } else {
        values = [];
    }
    return values;
}

function getStateInPreTokenRule() {
    // Reads the Code (Or if that fails the Refresh Token) from the STSUU
    var token = getAttributeValue("code", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, null) || getAttributeValue("refresh_token", "urn:ibm:names:ITFIM:oauth:body:param", CONTEXT, null)

    // Uses the token string to get the Token object from the DB.  Once we have that - we can read the StateId
    if (token != null) {
        grant = OAuthMappingExtUtils.getToken(token);
        if (grant != null) {
            return "" + grant.getStateId();
        }
    }
}

/**
 * Base64 Encode/Decode
 */
var base64 = new function () {
    this.decode = function (string) {
        return "" + new java.lang.String(java.util.Base64.getMimeDecoder().decode(string));
    }
    this.encode = function (string) {
        var sfar = java.lang.reflect.Array.newInstance(java.lang.String, 1);
        sfar[0] = string;
        return "" + java.util.Base64.getEncoder().encodeToString(sfar[0].getBytes());
    }
}