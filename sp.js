//
// OIDC Demo SP - Easy to customize SP for PoC and analysis purposes
//    DO NOT USE THIS IN ANY REGARD AS "PRODUCTION" SOFTWARE!!!
//
//    As this implementation uses a rudimentary state machine for implemented attacks, it is UNSAFE to use it with multiple users one instance
//
// Lauritz Holtmann 2020
// https://security.lauritz-holtmann.de/
//

// file system
const fs = require('fs');

// some IdPs require TLS
const https = require("https");
const options = {
  key: fs.readFileSync("my-key.key"),
  cert: fs.readFileSync("my-certificate.crt")
};

// We need another library for the backchannel communication + a library to craft the POST body
const http = require('http');
const querystring = require('querystring');
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0; // disable certificate validation, always a good idea ^^

// If we do not modify crypto related stuff, we may use a JWT library that does the heavy lifting for us
const useJWTLib = false; // set to false to explore JWT validation (crypto-wise)
const jwt = require("jsonwebtoken");
const privateKey = fs.readFileSync("private_unencrypted.pem", "utf-8");
const publicKey = fs.readFileSync("public.pem", "utf-8");
// Otherwise we craft the id_token using Node.js "crypto" + we need to encode stuff base64url manually
const crypto = require("crypto");
const base64url = require('base64url');

// Express.js web framework
const express = require("express");
let app = express();
app.disable('view cache');
app.use(express.urlencoded());
const nocache = require('nocache');
app.use(nocache());

/////////////////////////////////////////////////////////////////////////////////////////

// "state machine"
let redeem_code = true;

// Constants
//// IdP endpoints - add "127.0.0.1 poc.local" to your /etc/hosts file!
let authEndpoint = "https://poc.local:3001/auth";
let tokenEndpoint = "https://poc.local:3001/token";

//// SP endpoints
const landingEndpoint = "https://poc.local:4001";
const startFlowEndpoint = "https://poc.local:4001/start";
const redirectUriEndpoint = "https://poc.local:4001/callback";
const useCodeEndpoint = "https://poc.local:4001/use_code";
const getCodeEndpoint = "https://poc.local:4001/get_code";
const jwksEndpoint = "https://poc.local:4001/jwks";
const configurationEndpoint = "https://poc.local:4001/configure";

//// client authentication and credentials
let client_id = "test.local";
let client_secret = "supersecret";

function createJWT(payload, secret, choice) {
  if(useJWTLib === true) {
    return jwt.sign(payload, privateKey, {algorithm: 'RS256'});
  } else {
    // crypto related attacks may be realized using this block
    let header, toBeSigned;
    switch (choice) {
      case 1:
        // "None" Algorithm: Exclude Signature (alternatively append Junk)
        header = {"alg": "none", "typ": "JWT"}
        return base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));
      case 2:
        // HS256 hmac generation (e.g. using asymmetric key parameters as secret)
        header = {"alg": "HS256", "typ": "JWT", "kid": "test"}

        // Prepare signed part of the JWT
        toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

        let hmac = crypto.createHmac("sha256", secret).update(toBeSigned).digest("base64");;
        // we need base64url, thus we escape manually
        hmac_escaped = base64url.fromBase64(hmac);
        return toBeSigned + "." + hmac_escaped;
      case 3:
        // Potential SSRF and Key Confusion headers
        header = {"alg": "RS256", "typ": "JWT", "kid": "test", "x5u": "https://security.lauritz-holtmann.de", "jku": "https://security.lauritz-holtmann.de", "x5c": "junk", "jwk":  {"kty":"RSA","e":"AQAB","kid":"test2","use":"sig","n":"2PgMqqd9"}};
      default:
        // RS256 signature generation using private key as secret -> this results in valid signed token
        if(header === undefined) header = {"alg": "RS256", "typ": "JWT", "kid": "test"};

        // Prepare signed part of the JWT
        toBeSigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));

        const signer = crypto.createSign('RSA-SHA256');
        signer.write(toBeSigned);
        signer.end();
        let signature = signer.sign(secret, 'base64');
        // we need base64url, thus we escape manually
        signature_escaped = base64url.fromBase64(signature);
        return toBeSigned + "." + signature_escaped;
    }
  }
};
const jwt_payload = {
  "iss": client_id, 
  "sub": client_id, 
  "jti": "jti_static", 
  "aud": tokenEndpoint,
  "exp": (Date.now() /1000 |0) + 10000
}
// 0: client_secret_basic, 1: client_secret_post, 2: client_secret_jwt, 3: secret_key_jwt
let client_auth_choice = 1;
const client_secret_basic = "Basic " + Buffer.from(client_id + ":" + client_secret).toString('base64');

//// SP chosen values
let state = "state_static";
let nonce = "nonce_static";

//// IdP provided values
let code = "";
let access_token = "";
let refresh_token = "";
let id_token = "";

/////////////////////////////////////////////////////////////////////////////////////////
//// Request & Response Templates ///////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

let landingPage = `
<h1>Sample OIDC Service Provider</h1>

Entry Point:
<ul>
  <li><a href="${startFlowEndpoint}">${startFlowEndpoint}</a></li>
</ul>

Configuration:
<ul>
  <li><a href="${configurationEndpoint}">${configurationEndpoint}</a></li>
</ul>

All endpoints including some that might not accept direct access (new TAB):
<ul>
  <li><a href="${startFlowEndpoint}" target="_blank">${startFlowEndpoint}</a></li>
  <li><a href="${redirectUriEndpoint}" target="_blank">${redirectUriEndpoint}</a></li>
  <li><a href="${getCodeEndpoint}" target="_blank">${getCodeEndpoint}</a></li>
  <li><a href="${useCodeEndpoint}" target="_blank">${useCodeEndpoint}</a></li>
  <li><a href="${jwksEndpoint}" target="_blank">${jwksEndpoint}</a></li>
</ul>
`;

function configurePage() { 
  return `
<h1>Adjust Configuration</h1>

<b>This is completely unsafe, no input sanitization is performed at all.</b><br>

<form action="/configure" method="POST">
  <label for="client_id">client_id</label>:<br><input type="text" name="client_id" value="${client_id}"><br><br>
  <label for="client_secret">client_secret</label>:<br><input type="text" name="client_secret" value="${client_secret}"><br><br>
  <label for="auth_endpoint">Auth. Endpoint</label>:<br><input type="text" name="auth_endpoint" value="${authEndpoint}"><br><br>
  <label for="token_endpoint">Token Endpoint</label>:<br><input type="text" name="token_endpoint" value="${tokenEndpoint}"><br><br>
  <button type="submit">Submit</button>
</form>
<br>
<a href="/">Back to landing page</a>
`;
}

function callbackResponse() {
  return `
  <h1>OIDC flow completed</h1>

  Used code: 
  <ul>
    <li>code: ${code}</li>
  </ul>

  Obtained tokens:
  <ul>
    <li>access_token: ${access_token}</li>
    <li>refresh_token: ${refresh_token}</li>
    <li>id_token: ${id_token}</li>
  </ul>

  Possible actions:
  <ul>
    <li>Redeem (reuse) the above listed code: <a href="${useCodeEndpoint}">${useCodeEndpoint}</a></li>
    <li>Get a fresh code without redeeming it: <a href="${getCodeEndpoint}">${getCodeEndpoint}</a></li>
    <li>Start a new flow and redeem another fresh code: <a href="${startFlowEndpoint}">${startFlowEndpoint}</a></li>
  </ul>

  No User interaction Demo: 
  <button onclick="document.body.innerHTML=document.body.innerHTML+'<iframe src=/get_code></iframe><br>'">Click!</button>
  Explanation: We add an iFrame to the DOM using JavaScript. This could be done completely without user interaction, but for Demo purposes we do this "on click". <br><br>
  `;
}
function callbackResponse_unsend() {
  return `
  <h1>OIDC flow started</h1>

  We obtained a fresh code, but did not redeem it yet: 
  <ul>
    <li>code: ${code}</li>
  </ul>

  Possible actions:
  <ul>
    <li>Redeem the above listed code: <a href="${useCodeEndpoint}">${useCodeEndpoint}</a></li>
    <li>Get a fresh code without redeeming it: <a href="${getCodeEndpoint}">${getCodeEndpoint}</a></li>
    <li>Start a new flow and redeem another fresh code: <a href="${startFlowEndpoint}">${startFlowEndpoint}</a></li>
  </ul>
  `;
}

let jwksResponse = {"keys": [{"kty":"RSA","e":"AQAB","kid":"test","use":"sig","n":"2PgMqqd9_xLENUu1wBAU5HwxicxiARAHw62IwGaRIlmFT5VOjt6dTY2SWcVxIafc0_2pUmeNQFyINkOwEGDdmj6a4MPmb9NuHaCniJUFmteIECIfqCRMW_-EoDs4h8rGarrjbYA7QFtk2oTyqE55OSPQkRsTFgRDjkHp9gYlCcFPmdbSa_xIqWmkyn_sZGVxuH0B05-17d1UujTb5hIp5hMyVRDG0bcpdlSUHrA3VdKHrscwAacWw86_DJsPv62OjuqPy5wKGQv8ulxJS9XRx47tlTUqerTUs1wGqFq3Ei_lj7DQ448vPmADjnWINjujU15QH9rSBHxIzCoLJ93nfcmAoXSx0TiJbG4BbCgTAAUW_xmylUamqY6lpquNtPwYysbgacVlhlsPGKNYqwseuQ1J7I_M3fleTi4_Sz9JHDWLQuKJ_Jxa7qcQLhmfg1s7fZZ_eNurrJcSbD9qPxa7K1SDNtHsGgOdSxUzcrOe4sFkP9gejG2vj4xqBw1-gdvnfbzcCKJ57EHQAuK9-cDtVWAABX0zaCrUFamCp01oYBi_T5ClLk1Yd-Hn_59U4PtWlDkifiCzI5aajqZV8f4mvP05TMxGT0FegEOxUJ0A_QOaFH3Og58CjIG3_MslZqAbkGOsWWZMu0KLM0Cdz0jLRsarYMmwcD2GZRXjI6wJVs8"}]};

// dynamically generate the Token Request based on provided code + chosen client auth mechanism 
function tokenRequest() {
  let request_body = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirectUriEndpoint};

  switch(client_auth_choice) {
    case 0: // client_secret_basic
      return request_body;
    case 1: // client_secret_post
      return Object.assign(request_body, {"client_id": client_id, "client_secret": client_secret});
    case 2: // client_secret_jwt
      return Object.assign(request_body, {"client_assertion": createJWT(jwt_payload, client_secret, 2), "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"});
    case 3: // secret_key_jwt
      return Object.assign(request_body, {"client_assertion": createJWT(jwt_payload, privateKey, 0), "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}); // to use this option, register public key at IdP
  }
}

/////////////////////////////////////////////////////////////////////////////////////////
//// Endpoints //////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////

// landing page
app.get("/", function (req, res) {
  console.log(`  [${req.ip}] landing page`);
  
  res.send(landingPage);
});

// start endpoint - this endpoint has intentionally no CSRF protection
app.get("/start", function (req, res) {
  console.log(`  [${req.ip}] start OIDC flow`);

  let redirect_uri = new URL(authEndpoint);
  let params = new URLSearchParams();
  params.append("nonce", nonce);
  params.append("state", state);
  params.append("scope", "openid");
  params.append("response_type", "code");
  params.append("client_id", client_id);
  params.append("redirect_uri", redirectUriEndpoint);

  let redirect_target = redirect_uri + "?" + params.toString();
  console.log(`      [*] Redirect target: ${redirect_target}`);

  res.redirect(301, redirect_target);
});

let tokenResponse_chunks;
// redirect_uri endpoint
app.get("/callback", function (req, res) {
  console.log(`  [${req.ip}] redirect_uri endpoint`);

  code = req.query.code;

  if(redeem_code) {
    let data = querystring.stringify(tokenRequest());
    
    // send token request
    let tokenEndpointObject = new URL(tokenEndpoint);
    // we only need the authorization header if the client authentication mechanism to use is client_secret_basic
    let options;
    if(client_auth_choice === 0) {
      options = {host: tokenEndpointObject.hostname, port: tokenEndpointObject.port, path: tokenEndpointObject.pathname, method: "POST", headers: {"Authorization": client_secret_basic, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } };
    } else {
      options = {host: tokenEndpointObject.hostname, port: tokenEndpointObject.port, path: tokenEndpointObject.pathname, method: "POST", headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } };
    }
    console.log(`      [*] Request to be sent:\n        [-] Header: ${JSON.stringify(options)}\n        [-] Body: ${JSON.stringify(data)}`);
    try {
      // important: determine if SP uses http or https
      let dummy = https;
      if(tokenEndpointObject.protocol == "http:") dummy = http; 
      
      let httpreq = dummy.request(options, function (response) {
        tokenResponse_chunks = "";
        response.setEncoding('utf8');
        response.on('data', function (chunk) {
          tokenResponse_chunks += chunk;
          console.log(`      [*] Received chunk: ${chunk}`);
        });
        response.on('end', function() {
          console.log(`      [*] Received data: ${tokenResponse_chunks}`);
          //console.dir(response);
          let tokenResponse = JSON.parse(tokenResponse_chunks);
          access_token = tokenResponse.access_token;
          refresh_token = tokenResponse.refresh_token;
          id_token = tokenResponse.id_token;

          res.send(callbackResponse());
        })
      });
      httpreq.write(data);
      httpreq.end();
    } catch(e) {
      res.send("Whooops, that did not work... Something went wrong on Token Request :(")
    }
  } else {
    redeem_code = true;
    res.send(callbackResponse_unsend());
  }
});

// jwks endpoint
app.get("/jwks", function (req, res) {
  console.log(`  [${req.ip}] jwks endpoint`);
  console.log(`      [*] Data to be sent: ${JSON.stringify(jwksResponse)}`);

  res.json(jwksResponse);
});

// use_code endpoint - uses the currently known code to redeem a new access_token and id_token
app.get("/use_code", function (req, res) {
  console.log(`  [${req.ip}] use_code endpoint`);
  tokenResponse_chunks = "";

  let data = querystring.stringify(tokenRequest());
    
  // send token request
  let tokenEndpointObject = new URL(tokenEndpoint);
  // we only need the authorization header if the client authentication mechanism to use is client_secret_basic
  let options;
  if(client_auth_choice === 0) {
    options = {host: tokenEndpointObject.hostname, port: tokenEndpointObject.port, path: tokenEndpointObject.pathname, method: "POST", headers: {"Authorization": client_secret_basic, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } };
  } else {
    options = {host: tokenEndpointObject.hostname, port: tokenEndpointObject.port, path: tokenEndpointObject.pathname, method: "POST", headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } };
   }
  console.log(`      [*] Request to be sent:\n        [-] Header: ${JSON.stringify(options)}\n        [-] Body: ${JSON.stringify(data)}`);
  try {
    // important: determine if SP uses http or https
    let dummy = https;
    if(tokenEndpointObject.protocol == "http:") dummy = http;

    let httpreq = dummy.request(options, function (response) {
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        tokenResponse_chunks += chunk;
        console.log(`      [*] Received chunk: ${chunk}`);
      });
      response.on('end', function() {
        console.log(`      [*] Received response body: ${tokenResponse_chunks}`);
       
        let tokenResponse = JSON.parse(tokenResponse_chunks);
        access_token = tokenResponse.access_token;
        refresh_token = tokenResponse.refresh_token;
        id_token = tokenResponse.id_token;
      
        res.send(callbackResponse());
      })
    });
    httpreq.write(data);
    httpreq.end();
  } catch(e) {
    res.send("Whooops, that did not work... Something went wrong on Token Request :(")
  }
});

// get_code endpoint - starts a new login_flow but does not redeem the newly obtained fresh code
app.get("/get_code", function (req, res) {
  console.log(`  [${req.ip}] get_code endpoint`);
  redeem_code = false;

  res.redirect(301, startFlowEndpoint);
});

// Adjust configuration Endpoint - configure client_id and client_secret
app.get("/configure", function (req, res) {
  console.log(`  [${req.ip}] configure endpoint (GET)`);

  res.send(configurePage());
});

app.post("/configure", function (req, res) {
  console.log(`  [${req.ip}] configure endpoint (POST)`);

  client_id = req.body.client_id;
  client_secret = req.body.client_secret;
  authEndpoint = req.body.auth_endpoint;
  tokenEndpoint = req.body.token_endpoint;

  res.redirect(301, landingEndpoint);
});

/////////////////////////////////////////////////////////////////////////////////////////

app.listen(4000, function () {
  console.log("[+] Example SP listening for HTTP  on Port 4000 :-)");
});

https.createServer(options, app).listen(4001);
console.log("[+] Example SP listening for HTTPS on Port 4001 :-)");