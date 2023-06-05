# Simple Logger Function for Verify Access
A simple, easily searchable, standard logging object that can be used repeatably throughout mapping rules in Verify Access (or formally known as IBM Security Access Manager (ISAM)).

This logger function allows for simple integration into tools such as Logstash/Kibana.

## Importing Logger Utils

```javascript
importMappingRule("loggerUtils_lightweight"); 
```

> `loggerUtils.js` requires `standardUtils.js`. You MUST import this mapping rule or it will result in runtime exceptions.

```javascript
importMappingRule("standardUtils", "loggerUtils"); 
```

## Extracting Log Statements
To extract logger statements, simply run this `grep` over the `trace.log` file. This will pull out all matching lines into a new file called `result.log`.

```bash
grep -o '##Verify_Access_Logger_ver=1.0.0##.*' trace.log > result.log
```