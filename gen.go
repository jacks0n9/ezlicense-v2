package ezlicense

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

type adminLicenseProgram struct {
	LicenseHeader string
	PrivateKey    rsa.PrivateKey
}

// Generate a signed license
func (prog adminLicenseProgram) GenerateLicense(data LicenseData) (string, error) {
	encoded, err := toBase64Json(data)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(encoded))
	sig, err := rsa.SignPSS(rand.Reader, &prog.PrivateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return "", err
	}
	base64sig := base64.StdEncoding.EncodeToString(sig)
	licenseSigned := LicenseDataSigned{
		Data:      encoded,
		Signature: base64sig,
	}
	encodedLicense, err := json.Marshal(licenseSigned)
	if err != nil {
		return "", err
	}
	header := prog.LicenseHeader
	if header == "" {
		header = "LICENSE"
	}
	block := pem.Block{
		Type:  header,
		Bytes: []byte(encodedLicense),
	}
	licensePem := pem.EncodeToMemory(&block)
	return string(licensePem), nil
}

// Using an existing private key, create an admin license program
func LoadAdminLicenseProgram(key rsa.PrivateKey, header string) adminLicenseProgram {
	return adminLicenseProgram{
		PrivateKey:    key,
		LicenseHeader: header,
	}

}

// Create an admin license program with a new keypair
func NewAdminLicenseProgram(header string, keyLength int64) (*adminLicenseProgram, error) {
	key, err := rsa.GenerateKey(rand.Reader, int(keyLength))
	if err != nil {
		return nil, err
	}
	return &adminLicenseProgram{
		PrivateKey:    *key,
		LicenseHeader: header,
	}, nil
}
