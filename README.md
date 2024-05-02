# DeiC SSH Certificate Authority Library

Deic SSHCA library is a go library for making a service that issues SSH certificates based on a web login and a public SSH key.

For an introduction to SSH certificates see [If you’re not using SSH certificates you’re doing SSH wrong](https://smallstep.com/blog/use-ssh-certificates/)

One installation/service supports having multiple SSH certificate authorities - each with it's own key.

It supports two ways of issuing SSH certificates:
1. Using a web api with a access token and a SSH public key as parameters.
1. Using SSH for implicitly providing a SSH public key together with a token that maps it to the userinfo provided by the web login.

Using SSH the library supports two modes of operation:

Web first:
1. Do a web login - the service now has access to user info for the user
2. The service creates a token and a SSH command with the token in that is shown in the browser
3. The command is copied from the browser and pasted into a shell
4. The SSH command implicitly "uploads" the SSH public key - only ed25519 is currently supported
5. The service creates a certificate based on the user info from the web login that the token gives access to and the public SSH key.
6. The SSH certificate is sent down the SSH connection and put in an appropriate place

Shell first - using a simple shell function:
1. Establish a SSH connection to the service
2. The service creates the token and it is sent back to the shell as part of an url pointing to the web side of the service
3. The url is either auto opened or just echoed so that it can be clicked on or copied and pasted into a browser
4. The browser finishes the web login
5. The service creates a certificate based on the user info from the web login that the token gives access to and the SSH public key from the still open SSH connection
6. The SSH certificate is sent down the SSH connection and put in an appropriate place

## Running the demo
Running as a production service requires access to a HSM to secure the private keys for the SSH certificate authorities, but it is possible to kick the tires by running this repo in demo mode. As the web api requires access to a real OP and some additional configuration the demo currently only shows the SSH method.

The demo mode uses a SSH key from a local ssh-agent for both the  ssh server part and as a signing key for the ssh certificate authority, in addition to the normal use as the client key. The demo mode only has one tenant "demoCA" and it bypasses the web login by providing a fake username.

Running the demo requires:
- a go compiler - minimum version 1.22
- an ed25519 bare key in the local ssh-agent
- localhost is used for accessing respectively the webserver on http://localhost:2280 and SSH on port 2221. This is the default host name in the configuration - change it if you need.

So clone the repo and:

- run: `go run cmd/main.go` in the local clone
- open [http://localhost:2280](http://localhost:2280) in a browser
- choose "Demo CA"
- click "Login with a fake principal"
- copy the ssh command and run it in a shell - be aware that it will overwrite ~/.ssh/id_ed25519-cert.pub
- the browser will show a dump of the downloaded certificate as feedback
- run: `ssh -p 2221 demo@localhost demo` to se a dump of the certificate your SSH client would use if you tried to log in to a SSH server that required a ed25519 SSH certificate.

If you want to test starting the issuing of a certificate in a shell add the following function:

```shell
sshca () { ssh -p 2221 localhost ca -ca=demoCA | (read uri; open $uri;  >  ~/.ssh/id_ed25519-cert.pub) }
```

You should replace the `open` with whatever opens an url on your platform. `open` works on a Mac.

Then run: `sshca` and then click "Login with a fake principal" in the browser.

The sshca function is supposed to download the certificate and the browser to show a dump of the certificate as feedback.

Then run: `ssh -ssh -p 2221 demo@localhost demo` to se a dump of the certificate your ssh client would use if you tried to log in to a ssh server that required a ed25519 SSH certificate.

 


 

