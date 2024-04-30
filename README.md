# DeiC SSH Certificate Authority Library

Deic SSHCA library is a go library for issuing SSH certificates based on a web login and a public SSH key.

For an introduction to SSH certificates see [If you’re not using SSH certificates you’re doing SSH wrong](https://smallstep.com/blog/use-ssh-certificates/)

It supports two ways of issuing SSH certificates:
1. Using a web api with a access token and a SSH public key as parameters.
1. Using ssh for implicitly providing a SSH public key together with a token that maps it to the userinfo provided by the web login.

It supports having multiple CA tenants in one installation.

Running as a production service requires access to a HSM to secure the private keys for the SSH certificate authorities, but it is possible to kick the tires by running this repo in demo mode. As the web api requires access to a real OP and some additional configuration the demo only shows the ssh method.

The demo mode uses a ssh key from a local ssh-agent for both the  ssh server part and for the CA, in addition to the normal use as the client key. The demo mode only has one CA and it bypasses the web login by providing a fake username.

## Running the demo

Running the demo requires:
- a go compiler - minimum version 1.22
- an ed25519 bare key in the local ssh-agent
- localhost is used for accessing respectively the webserver on http://localhost:2280 and ssh on port 2221. This is the default host name in the configuration - change it if you need.

So clone the repo and:

- run: `go run cmd/main.go` in the local clone
- open [http://localhost:2280](http://localhost:2280) in a browser
- choose "Demo CA"
- click "Login with a fake principal"
- copy the ssh command and run it in a shell - be aware that it will overwrite ~/.ssh/id_ed25519-cert.pub
- the browser will show a dump of the downloaded certificate as feedback
- run: `ssh -p 2221 demo@localhost demo` to se a dump of the certificate your ssh client would use if you  tried to log in to a ssh server that required a ed25519 SSH certificate.

If you want to test starting the issuing of a certificate in a shell add the following function:

`sshca () { ssh -p 2221 localhost ca -ca=demoCA | (read uri; open $uri;  >  ~/.ssh/id_ed25519-cert.pub) } `

You should replace the `open` with whatever opens an url on your platform. `open` works on a Mac.

Then run: `sshca` and then click "Login with a fake principal" in the browser.

The sshca function is supposed to download the certificate and the browser to show a dump of the certificate as feedback.

Then run: `ssh -ssh -p 2221 demo@localhost demo` to se a dump of the certificate your ssh client would use if you  tried to log in to a ssh server that required a ed25519 SSH certificate.

 


 

