package ezlicense

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

func toBase64Json(data interface{}) (string, error) {
	inJson, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(inJson)
	return encoded, nil
}
func fromBase64Json(input string, out any) error {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	err = json.Unmarshal(decoded, &out)
	if err != nil {
		return err
	}
	return nil
}

// Read a pem-encoded public key
func ReadPemPublicKey(input string) (*rsa.PublicKey, error) {
	decoded, _ := pem.Decode([]byte(input))
	return x509.ParsePKCS1PublicKey(decoded.Bytes)

}

// Read a pem-encoded private key
func ReadPemPrivateKey(input string) (*rsa.PrivateKey, error) {
	decoded, _ := pem.Decode([]byte(input))
	return x509.ParsePKCS1PrivateKey(decoded.Bytes)
}

// Export a public key to pem
func ExportPublicKey(pub rsa.PublicKey) string {
	marshalled := x509.MarshalPKCS1PublicKey(&pub)
	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	}
	encoded := pem.EncodeToMemory(&block)
	return string(encoded)
}

// Export a private key to pem
func ExportPrivateKey(private rsa.PrivateKey) string {
	marshalled := x509.MarshalPKCS1PrivateKey(&private)
	block := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshalled,
	}
	encoded := pem.EncodeToMemory(&block)
	return string(encoded)
}

// The useful data of a license, decoded and without a signature
type LicenseData struct {
	Expires        int64                  `json:"expires"`
	AdditionalData map[string]interface{} `json:"additional_data"`
}

// An intermediate struct to represent the contents of the license
type LicenseDataSigned struct {
	// base64 encoded json
	Data string `json:"data"`
	// base64 signature
	Signature string `json:"signature"`
}
