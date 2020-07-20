# Custom OpenID Connect Service Provider
Custom and flexible OpenID Connect SP for research and PoC purposes - built with Node.js.


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

