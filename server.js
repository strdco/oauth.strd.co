#!/usr/bin/env node



// Core modules:
const https = require('https');
const { URL } = require('url');

// Other modules:
const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');

// HTTP port that the server will run on:
var serverPort=process.argv[2] || process.env.PORT || 3000;

// The web server itself:
const app = express();
app.disable('etag');
app.disable('x-powered-by');
app.disable('trust proxy'); // this breaks the rate limiting

app.use(express.json());
app.use(express.urlencoded( { extended: true }));

const apiRateLimiter = rateLimit({
    windowMs: 2 * 60 * 1000, // 2 minutes
    max: 10, // Limit each IP to 10 requests per time window
    message: {
      status: 'error',
      message: 'Too many requests, please try again later.'
    },
    standardHeaders: false, // Rate limit info in "RateLimit-*" headers
    legacyHeaders: false, // Legacy "X-RateLimit-*" headers

    // Optional: customize the handler for rate limit exceeded
    handler: (req, res, next, options) => {
      res.status(options.statusCode).send(options.message);
    },
});









function sendFileOptions(root, maxAge) {

    return({
        maxAge: 24 * 60 * 60 * 1000,         // 24 little hours
        root: __dirname + (root || '/assets/'),
        dotfiles: 'deny',
        headers: {
            'x-timestamp': Date.now(),
            'x-sent': true
        }
    });
}



/*-----------------------------------------------------------------------------
  Start the web server
-----------------------------------------------------------------------------*/

console.log('');
console.log('HTTP port:       '+serverPort);
console.log('Express env:     '+app.settings.env);
console.log('');
console.log('');

app.listen(serverPort, () => console.log('READY.'));






/*-----------------------------------------------------------------------------
  Default URL: redirect to the admin page.
  ---------------------------------------------------------------------------*/

app.get('/', function (req, res, next) {
    httpHeaders(res);

    res.status(200).sendFile('index.html', sendFileOptions('/assets/', 60 * 60 * 1000), function(err) {
        if (err) {
            res.sendStatus(404);
            return;
        }
    });

    return;

});





/*-----------------------------------------------------------------------------
  Other related assets, like images, CSS or other files.

  They should all be in the "assets" folder, in order to prevent a malicious
  actor from accessing them.
  ---------------------------------------------------------------------------*/

app.get('/:asset', function (req, res, next) {
    httpHeaders(res);
    
    // Becuase I'm paranoid
    const asset=req.params.asset.split('/').join('');

    res.status(200).sendFile(asset, sendFileOptions('/assets/', 60 * 60 * 1000), function(err) {
        if (err) {
            res.sendStatus(404);
            return;
        }
    });
});




















// Save responses - fires every time a user makes/changes a selection
app.post('/proxy', apiRateLimiter, async function (req, res, next) {

    httpHeaders(res);

    var requestIsValid=false;

console.log(req.body);

    // authorization_code
    if (req.body.client_id!='' && req.body.client_secret!='' &&
        req.body.code!='' && req.body.grant_type=='authorization_code' &&
        req.body.redirect_url!='') { requestIsValid=true; }

    // refresh_token
    if (req.body.client_id!='' && req.body.client_secret!='' &&
        req.body.grant_type=='refresh_token' &&
        req.body.refresh_token!='') { requestIsValid=true; }
    
    // client_credentials
    if (req.body.client_id!='' && req.body.client_secret!='' &&
        req.body.grant_type=='client_credentials' &&
        req.headers.Authorization) { requestIsValid=true; }

    if (!requestIsValid) {
        res.status(400).send({ "status": "error", "message": "Bad request." });
        return;
    }

    var postHeaders = {
        // Standard forwarded header (RFC 7239)
        'Forwarded': `for=${req.ip};proto=${req.protocol};host=${req.get('host')}`,
        
        // Legacy X-Forwarded headers for broader compatibility
        'X-Forwarded-For': req.ip,
        'X-Forwarded-Host': req.get('host'),
        'X-Forwarded-Proto': req.protocol,
        
        // Additional context
        'X-Original-Client-IP': req.ip,
        'X-Request-Start': Date.now().toString()
    }

    if (req.headers.Authorization) {
        postHeaders.Authorization = req.body.Authorization;
    }

    let postData = new URLSearchParams(req.body);
    postData.delete('proxy_target');

    try {
        console.log('POSTing to '+req.body.proxy_target);
        console.log(postData.toString());
        console.log(postHeaders);
        console.log('---');
        var authResponse = await proxyRequest(req.body.proxy_target, {
            "method": "POST",
            "data": postData.toString(),
            "headers": postHeaders
        });

        res.status(authResponse.statusCode).send(authResponse.body);
    } catch(e) {
        console.log(e);
        res.status(500).send({
            "status": "proxy_error",
            "message": "Something went wrong with the proxy request.",
            "details": e});
    }
});






// Collect data from the Sessionize endpoint
async function proxyRequest(targetUrl, options = {}) {
    const {
        method = 'POST',
        data = '',
        headers = {}
    } = options;
    
    // Parse the URL
    const url = new URL(targetUrl);

    // Prepare request options
    const requestOptions = {
        hostname: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
            'User-Agent': 'auth.strd.co',
            ...headers
        }
    };

    return new Promise((resolve, reject) => {
        // Create the request
        const req = https.request(requestOptions, (res) => {
            let responseBody = '';
    
            // Accumulate response data
            res.on('data', (chunk) => {
                responseBody += chunk;
            });

            // Response complete
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: responseBody
                });
            });
        });

        // Handle network errors
        req.on('error', (error) => {
            reject(error);
        });

        // Set timeout
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });

        // Write request body if data provided
        if (data.length > 0) {
            req.setHeader('Content-Length', Buffer.byteLength(data));
            req.write(data);
        }

        // End the request
        req.end();
    });
}







/*-----------------------------------------------------------------------------
  A bunch of HTTP headers we want to return:
  ---------------------------------------------------------------------------*/

function httpHeaders(res) {

    // Limits use of external script/css/image resources
    // Don't allow this site to be embedded in a frame; helps mitigate clickjacking attacks
    res.header('X-Frame-Options', 'sameorigin');

    // Prevent MIME sniffing; instruct client to use the declared content type
    res.header('X-Content-Type-Options', 'nosniff');

    // Don't send a referrer to a linked page, to avoid transmitting sensitive information
    res.header('Referrer-Policy', 'no-referrer');

    // Limit access to local devices
    res.header('Permissions-Policy', "camera=(), display-capture=(), microphone=(), geolocation=(), usb=()"); // replaces Feature-Policy

    return;
}
