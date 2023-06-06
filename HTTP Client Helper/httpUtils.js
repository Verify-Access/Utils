/**
 * HTTP Client Helper function
 */

// Package imports
importPackage(Packages.com.ibm.security.access.httpclient);

const GET = "GET";
const POST = "POST";
const PUT = "PUT";
const PATCH = "PATCH";
const DELETE = "DELETE";

headers = null;
defaultTimeOut = -1;

/**
 * HTTP Client Helper for managing JSON requests and httpRequestResponses from back-end systems.
 */
var httpClientHelperV2 = new function () {

    /**
     * Get server connection details, e.g. `getUrl()`, `getUser()`, `getPasswd()`, etc.
     * @param {String} name Server connection name
     * @returns {Object} Server connection connection details
     */
    this.getServerConnection = function (name) {
        return ServerConnectionFactory.getWebConnectionByName(name);
    }

    this.setupInitialHeaders = function () {
        if (!headers) {
            headers = new Headers();
            headers.addHeader('Content-Type', 'application/json');
            headers.addHeader('Accept', 'application/json');
        }

        return headers;
    }

    this.jsonToParams = function (jsonObject) {
        parameters = new Parameters();

        for (property in jsonObject) {
            parameters.addParameter("" + property, "" + jsonObject[property])
        }
        return parameters;
    }

    // Configure authorization headers.
    this.authorization = new function () {
        /**
         * Sets a "Bearer" HTTP authentication header with the signed JSON Web Token (JWT).
         * @param {String} apiToken A signed JSON Web Token (JWT)
         */
        this.bearer = function (apiToken) {
            headers.addHeader('Authorization', 'Bearer ' + apiToken);
        }

        /**
         * Sets a custom HTTP authentication header with the signed JSON Web Token (JWT).
         * @param {String} apiHeader Header name
         * @param {String} apiToken A signed JSON Web Token (JWT)
         */
        this.customAccessToken = function (apiHeader, apiToken) {
            headers.addHeader(apiHeader, apiToken)
        }

        /**
         * Sets a "Basic" HTTP authentication header, which transmits credentials as user ID/password pairs, encoded using base64.
         * @param {String} username User ID in clear text
         * @param {String} password Password in clear text
         */
        this.basic = function (username, password) {
            if (connection.getUser() != null || connection.getPasswd() != null || headers.getHeader('Authorization') == null) {
                headers.addHeader('Authorization', 'Basic ' + base64Encode(username + ':' + password));
            }
        }
    }

    /**
     * Overwrite the default value set in the advanced configuration property util.httpClientv2.connectTimeout.
     * @param {int} seconds Request timeout in seconds. A value of `0` will result in no connection timeout.
     */
    this.timeOut = function (seconds) {
        defaultTimeOut = seconds;
    }


    this.httpRequest = function (method, urlStr, parametersObject) {
        this.setupInitialHeaders();
        logger.log(VERBOSE, "HttpClientHelperV2.httpRequest. method: " + method + ". url: " + urlStr + ". headers: " + headers.getHeaders().toString() + ". parameters: " + JSON.stringify(parametersObject) + ".");
        httpRequestResponse = null;
        returnObject = {};
        returnObject.success = false;
        returnObject.code = 500;
        returnObject.body = {};
        // returnObject.headers = "";

        logger.startTimer(urlStr);
        switch (method) {
            case GET:
                // httpRequestResponse = HttpClient.httpGet(url, headers, null, null, null, null, null);
                httpRequestResponse = HttpClientV2.httpGet(
                    urlStr, // URL
                    headers, // Headers to be added to the request header.
                    null, // httpsTrustStore - The name of the trust store to use. If a HTTPS connection is required and this is set to NULL, the default trust store specified in the advanced configuration parameter util.httpClientv2.defaultTrustStore will be used.
                    null, // basicAuthUsername - Basic-auth username. If null, basic-auth will be disabled.
                    null, // basicAuthPassword - Basic-auth password. If null, basic-auth will be disabled.
                    null, // clientKeyStore - Client key store. If null, client cert auth will be disabled.
                    null, // clientKeyAlias - Client key alias. If null, client cert auth will be disabled.
                    null, // protocol - SSL protocol to use for this connection. Valid values are: TLS, TLSv1, TLSv1.1, TLSv1.2. If not provided the value of the advanced configuration property 'util.httpClient.defaultSSLProtocol' will be used. FIPS and NIST mode will override this value.
                    false, // throwExec - If an exception should be raised, or handled
                    defaultTimeOut, // timeout - Request timeout in seconds A value of 0 will result in no connection timeout. If set to a value less than 0 the timeout will be set as the advanced configuration property util.httpClientv2.connectTimeout.
                    null // proxyServer - The full name of the proxy server to use. Eg: https://proxy.com:443. Set as null if a proxy server is not required.
                );
                break;
            case POST:
                httpRequestResponse = HttpClientV2.httpPost(
                    urlStr, // URL
                    headers, // Headers to be added to the request header.
                    this.jsonToParams(parametersObject), // Parameters to be added to the request body.
                    null, // httpsTrustStore - The trust store to use. If a HTTPS connection is required and this is set to NULL, the default trust store specified in the advanced configuration parameter util.httpClientv2.defaultTrustStore will be used.
                    null, // basicAuthUsername - Basic-auth username. If null, basic-auth will be disabled.
                    null, // basicAuthPassword - Basic-auth password. If null, basic-auth will be disabled.
                    null, // clientKeyStore - Client key store. If null, client cert auth will be disabled.
                    null, // clientKeyAlias - Client key alias. If null, client cert auth will be disabled.
                    null, // protocol - SSL protocol to use for this connection. Valid values are: TLS, TLSv1, TLSv1.1, TLSv1.2. If not provided the value of the advanced configuration property 'util.httpClient.defaultSSLProtocol' will be used. FIPS and NIST mode will override this value.
                    false, // throwException - If an exception should be raised, or handled
                    defaultTimeOut, // timeout - Request timeout in seconds A value of 0 will result in no connection timeout. If set to a value less than 0 the timeout will be set as the advanced configuration property util.httpClientv2.connectTimeout.
                    true, // sendDataAsJson - If the post data should be json formatted or not.
                    null // proxyServer - The full name of the proxy server to use. Eg: https://proxy.com:443. Set as null if a proxy server is not required.
                );
                break;
            case PUT:
                httpRequestResponse = HttpClientV2.httpPut(
                    urlStr, // URL
                    headers, // Headers to be added to the request header.
                    this.jsonToParams(parametersObject), // Parameters to be added to the request body.
                    null, // httpsTrustStore - The trust store to use. If a HTTPS connection is required and this is set to NULL, the default trust store specified in the advanced configuration parameter util.httpClientv2.defaultTrustStore will be used.
                    null, // basicAuthUsername - Basic-auth username. If null, basic-auth will be disabled.
                    null, // basicAuthPassword - Basic-auth password. If null, basic-auth will be disabled.
                    null, // clientKeyStore - Client key store. If null, client cert auth will be disabled.
                    null, // clientKeyAlias - Client key alias. If null, client cert auth will be disabled.
                    null, // protocol - SSL protocol to use for this connection. Valid values are: TLS, TLSv1, TLSv1.1, TLSv1.2. If not provided the value of the advanced configuration property 'util.httpClient.defaultSSLProtocol' will be used. FIPS and NIST mode will override this value.
                    false, // throwException - If an exception should be raised, or handled
                    defaultTimeOut, // timeout - Request timeout in seconds A value of 0 will result in no connection timeout. If set to a value less than 0 the timeout will be set as the advanced configuration property util.httpClientv2.connectTimeout.
                    true, // sendDataAsJson - If the post data should be json formatted or not.
                    null // proxyServer - The full name of the proxy server to use. Eg: https://proxy.com:443. Set as null if a proxy server is not required.
                );
                break;
            case PATCH:
                httpRequestResponse = HttpClientV2.httpPatch(
                    urlStr, // URL
                    headers, // Headers to be added to the request header.
                    this.jsonToParams(parametersObject), // Parameters to be added to the request body.
                    null, // httpsTrustStore - The trust store to use. If a HTTPS connection is required and this is set to NULL, the default trust store specified in the advanced configuration parameter util.httpClientv2.defaultTrustStore will be used.
                    null, // basicAuthUsername - Basic-auth username. If null, basic-auth will be disabled.
                    null, // basicAuthPassword - Basic-auth password. If null, basic-auth will be disabled.
                    null, // clientKeyStore - Client key store. If null, client cert auth will be disabled.
                    null, // clientKeyAlias - Client key alias. If null, client cert auth will be disabled.
                    null, // protocol - SSL protocol to use for this connection. Valid values are: TLS, TLSv1, TLSv1.1, TLSv1.2. If not provided the value of the advanced configuration property 'util.httpClient.defaultSSLProtocol' will be used. FIPS and NIST mode will override this value.
                    false, // throwException - If an exception should be raised, or handled
                    defaultTimeOut, // timeout - Request timeout in seconds A value of 0 will result in no connection timeout. If set to a value less than 0 the timeout will be set as the advanced configuration property util.httpClientv2.connectTimeout.
                    true, // sendDataAsJson - If the post data should be json formatted or not.
                    null // proxyServer - The full name of the proxy server to use. Eg: https://proxy.com:443. Set as null if a proxy server is not required.
                );
                break;
            case DELETE:
                httpRequestResponse = HttpClientV2.httpDelete(
                    urlStr, // URL
                    headers, // Headers to be added to the request header.
                    null, // httpsTrustStore - The trust store to use. If a HTTPS connection is required and this is set to NULL, the default trust store specified in the advanced configuration parameter util.httpClientv2.defaultTrustStore will be used.
                    null, // basicAuthUsername - Basic-auth username. If null, basic-auth will be disabled.
                    null, // basicAuthPassword - Basic-auth password. If null, basic-auth will be disabled.
                    null, // clientKeyStore - Client key store. If null, client cert auth will be disabled.
                    null, // clientKeyAlias - Client key alias. If null, client cert auth will be disabled.
                    null, // protocol - SSL protocol to use for this connection. Valid values are: TLS, TLSv1, TLSv1.1, TLSv1.2. If not provided the value of the advanced configuration property 'util.httpClient.defaultSSLProtocol' will be used. FIPS and NIST mode will override this value.
                    false, // throwException - If an exception should be raised, or handled
                    defaultTimeOut, // timeout - Request timeout in seconds A value of 0 will result in no connection timeout. If set to a value less than 0 the timeout will be set as the advanced configuration property util.httpClientv2.connectTimeout.
                    true, // sendDataAsJson - If the post data should be json formatted or not.
                    null // proxyServer - The full name of the proxy server to use. Eg: https://proxy.com:443. Set as null if a proxy server is not required.
                );
                break;
            default:
                OAuthMappingExtUtils.throwSTSCustomUserMessageException("Method not supported", 400, "invalid_request");
                break;
        }

        logger.stopTimer(urlStr);

        if (httpRequestResponse) {
            logger.log(VERBOSE, "HttpClientHelperV2.httphttpRequestResponse. url: " + urlStr + ". code: " + httpRequestResponse.getCode() + ". headers: " + httpRequestResponse.getHeaders().toString() + ". body: " + httpRequestResponse.getBody() + ".");

            // Add the response HTTP code.
            if (typeof httpRequestResponse.getCode() === "number") {
                returnObject.code = httpRequestResponse.getCode();
            }
            returnObject.success = (("" + returnObject.code).match(/^2\d\d$/)) ? true : false // Matches on HTTP 2XX and returns `true`.

            // Add HTTP response headers.
            //returnObject.headers = "" + httpRequestResponse.getHeaders().toString();

            // Attempting to parse the JSON response.
            try {
                returnObject.body = JSON.parse('' + httpRequestResponse.getBody());
            } catch (error) {
                returnObject.body = "" + httpRequestResponse.getBody();
            }

            return returnObject;
        } else {
            // We didn't get an HTTP response.
            logger.log(ERROR, "Didn't receive a HttpClientHelperV2.httphttpRequestResponse.")
            return returnObject;
        }
    };
}
