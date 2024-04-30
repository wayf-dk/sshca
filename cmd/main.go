package main

import (
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
		Verification_uri_template: "http://localhost:2280/%s\n",
		RendevouzTTL:              30,
		SshListenOn:               "localhost:2221",
		WebListenOn:               "localhost:2280",

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

