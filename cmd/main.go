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
		HTMLTemplate:              "login",
		Verification_uri_template: "http://localhost:2280/%s\n",
		SSOTTL:                    "3m",
		RendevouzTTL:              "1m",
		SshListenOn:               "localhost:2221",
		WebListenOn:               "localhost:2280",

		CaConfigs: map[string]sshca.CaConfig{
			"demoCA": {
				Fake:      true,
				Name:      "Demo CA",
				Signer:    signer,
				PublicKey: publicKey,
				CAParams: sshca.CAParams{
					Ttl: 500,
				},
			},
			"transport": {
				Signer: signer,
			},
		},
	}

	sshca.Sshca()
}
