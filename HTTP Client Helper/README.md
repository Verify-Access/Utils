# HTTP Client Helper Function for Verify Access
A simple, HTTP client helper, leveraging the `httpClientHelperV2` class, that can be used throughout mapping rules in Verify Access (or formally known as IBM Security Access Manager (ISAM)).

The `httpClientHelperV2()` function simplifies making calls to other API's.

> This HTTP Client Helper function requires [Logger Utils](https://github.com/anthonygaliamov/Verify-Access/tree/main/Logger) for the `logger()` functions.

## Importing HTTP Client Helper Utils

```javascript
importMappingRule("httpUtils", "loggerUtils_lightweight");
```

## Making a HTTP Request

```javascript
// To make a GET request:
httpClientHelperV2.httpRequest(GET, "https://api.server.com")

// To make a POST request:
claims = {}
claims.id = "12345"
claims.message = "string"
httpClientHelperV2.authorization.basic("user", "password")
httpClientHelperV2.httpRequest(POST, "https://api.server.com/update", claims)
```