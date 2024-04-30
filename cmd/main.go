package main

import (
    "fmt"
	_ "embed"
	"sshca"
)

var (
    //go:embed ca.template
	tmpl string
)

func main() {
	publicKey, signer := sshca.GetSignerFromSshAgent()

	sshca.Config = sshca.Conf{
		Template:                  tmpl,
		Verification_uri_template: "http://sshca.lan:2280/%s\n",
		RendevouzTTL:              30,
		SshListenOn:               "sshca.lan:2221",
		WebListenOn:               "sshca.lan:2280",

		CaConfigs: map[string]sshca.CaConfig{
			"demoCA": {
			    Fake:      true,
			    Name:      "Demo CA",
				Signer:    signer,
				PublicKey: publicKey,
				Settings: sshca.Settings {
    				Ttl:    36 * 3600,
				},
			},
            "transport": {
                Signer: signer,
            },
		},
	}

	sshca.Sshca()
}

