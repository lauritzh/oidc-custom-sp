# Custom OpenID Connect Service Provider
Custom and flexible OpenID Connect SP for research and PoC purposes - built with Node.js.

**Disclaimer**: *Any information shared within this repository must not be used with malicious intentions. Proof-of-Concepts and tools are shared for educational purpose only. Any malicious use will not hold the author responsible.*

## Setup
```Bash
user@laptop:/$ git clone https://github.com/lauritzh/oidc-custom-sp
[...]
user@laptop:/$ cd oidc-custom-sp/
user@laptop:/oidc-custom-sp$ node sp.js 
[+] Example SP listening for HTTPS on Port 4001 :-)
[+] Example SP listening for HTTP  on Port 4000 :-)

```
(This requires Node.js on your machine)

You may add "127.0.0.1 poc.local" to your `/etc/hosts`-file, so that you can reach the SP at https://poc.local:4001/

## Intercepting Proxy
By using the [global-agent](https://github.com/gajus/global-agent) Node.js module, it is possible to intercept the backend traffic such as the *Token Request* and *Userinfo Request*:

```bash
$ npm i global-agent
$ export GLOBAL_AGENT_HTTP_PROXY=http://127.0.0.1:8080
$ node -r 'global-agent/bootstrap' sp.js 
```
