package main

import (
	_ "embed"
	"os"
	"github.com/wayf-dk/sshca"
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
		SshPort:                   "2221",
		UseRevProxy:               true,

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
    hostName, _ := os.Hostname()
    sshca.Host2PortRec = map[string]string{hostName: "2221",}
	sshca.Sshca()
}
