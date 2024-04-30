package sshca

import (
    "fmt"
	"io"
	"log"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh"
)

const (
	CKM_EDDSA = 0x80000c03 // not in pkcs11 yet
)

var (
	p        *pkcs11.Ctx
	tokenMap = map[string]uint{}
	sessions chan pkcs11.SessionHandle
)

// Signer
type hsmSigner struct {
	priv pkcs11.ObjectHandle
	pub  ssh.PublicKey
}

func InitPKCS11(pin string) {
    sessions = make(chan pkcs11.SessionHandle, Config.NoOfSessions)
	p = pkcs11.New(Config.Cryptokilib)
	if p == nil {
		log.Fatal("No cryptoki lib available")
	}
	fmt.Println("pkcs11.New")
	e := p.Initialize()
	if e != nil {
		log.Fatalf("pkcs11 Initialize failed %s", e.Error())
	}
	fmt.Println("pkcs11.Initialize")

	slotlist, e := p.GetSlotList(true)
	if e != nil {
		log.Fatalf("slots %s\n", e.Error())
	}

	for _, slot := range slotlist {
		tokeninfo, _ := p.GetTokenInfo(slot)
		tokenMap[tokeninfo.Label] = slot
	}

	fmt.Println("pkcs11.slotlist", tokenMap)

	for i := 0; i < Config.NoOfSessions; i++ {
		session, e := p.OpenSession(tokenMap[Config.Slot], pkcs11.CKF_SERIAL_SESSION)

		if e != nil {
			log.Fatalf("Failed to open session: %s\n", e.Error())
		}
        fmt.Println("session", session, e)
		e = p.Login(session, pkcs11.CKU_USER, pin)
		if e != nil {
			log.Printf("Failed to login to session: %s\n", e.Error())
		}
        fmt.Println("login",sessions,  e)
		sessions <- session
	}
	fmt.Println("pkcs11.end of init")

}

func findPrivatekey(label string) (pkcs11.ObjectHandle, bool) {
    if len(sessions) == 0 {
        log.Println("no HSM sessions available - HSM keys can't be used")
        return 0, false
    }
	session := <-sessions
	defer func() { sessions <- session }()
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	if err := p.FindObjectsInit(session, template); err != nil {
		log.Panicf("FindObjectsInit failed: %s", err.Error())
	}
	objs, b, err := p.FindObjects(session, 2)
	if err != nil {
		log.Panicf("FindObjects faild: %s %v", err.Error(), b)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		log.Panicf("indObjectsFinal failed: %s", err.Error())
	}
	if len(objs) != 1 {
		log.Panicf("did not find one (and only one) key with label '%s'", label)
	}
	return objs[0], true
}

func (signer hsmSigner) Sign(rand io.Reader, digest []byte) (signature *ssh.Signature, err error) {
	session := <-sessions
	defer func() { sessions <- session }()
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EDDSA, nil)}, signer.priv)
	log.Println("signinit", err)
	sig, err := p.Sign(session, digest)
	if err != nil {
		log.Fatalf("failed to sign: %s\n", err)
	}
	return &ssh.Signature{
		Format: signer.PublicKey().Type(),
		Blob:   sig,
	}, err
}

func (signer hsmSigner) PublicKey() ssh.PublicKey {
	return signer.pub
}
