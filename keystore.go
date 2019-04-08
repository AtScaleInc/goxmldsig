package dsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type X509KeyStore interface {
	GetKeyPair() (privateKey *rsa.PrivateKey, cert []byte, err error)
}

type X509ChainStore interface {
	GetChain() (certs [][]byte, err error)
}

type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func NewMemoryX509KeyStore(privKey *rsa.PrivateKey, cert []byte) *MemoryX509KeyStore {
	return &MemoryX509KeyStore{
		privateKey: privKey,
		cert:       cert,
	}
}

func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	now := time.Now()
	pkixName := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"AtScale"},
		OrganizationalUnit: []string{"Apps"},
		Locality:           []string{"Locality1"},
		Province:           []string{"province1"},
		StreetAddress:      []string{"street address"},
		PostalCode:         []string{"postal code"},
		SerialNumber:       "customserialnumber",
		CommonName:         "commonName",
	}

	// TODO: figure out how long we want these to be valid for
	// if a short time, then we want to afford them a button to regenerate certs
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		Issuer:                pkixName,
		Subject:               pkixName, // this will get used as the issuer value (should solve the empty issuer dn problemn)
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	_, err = x509.ParseCertificate(cert)
	if err != nil {
		panic(err)
	}

	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}
