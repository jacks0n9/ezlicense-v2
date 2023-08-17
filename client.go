package ezlicense

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"
)

type clientLicenseProgram struct {
	PublicKey    rsa.PublicKey
	TimeVerifier TimeVerifier
}

// An interface representing a type that can tell if the given time has passed yet
type TimeVerifier interface {
	VerifyTime(timeNum int64) error
}
type httpTimeVerifier struct {
	Url string
}

// Creates a time verifier that uses the data header returned from an http request to the given url
func NewHTTPTimeVerifier(url string) httpTimeVerifier {
	return httpTimeVerifier{
		Url: url,
	}
}

// Create an HTTPTimeVerifier using google.com as the trusted source
func NewDefaultTimeVerifier() TimeVerifier {
	return NewHTTPTimeVerifier("https://www.google.com")
}

// Create a license program for the client
func NewClientLicenseProgram(publicKey rsa.PublicKey, timeVerifier TimeVerifier) clientLicenseProgram {
	return clientLicenseProgram{
		PublicKey:    publicKey,
		TimeVerifier: timeVerifier,
	}
}
func (htv httpTimeVerifier) VerifyTime(timeNum int64) error {
	resp, err := http.Get(htv.Url)
	if err != nil {
		return err
	}
	date := resp.Header.Get("Date")
	parsed, err := time.Parse(time.RFC1123, date)
	if err != nil {
		return err
	}
	if parsed.After(time.Unix(timeNum, 0)) {
		return errors.New("expired license")
	}
	return nil
}

// Checks if a license is signed correctly and not expired
// Returns an error if the license fails to verify
func (clp clientLicenseProgram) VerifyLicense(license string) (*LicenseData, error) {
	block, _ := pem.Decode([]byte(license))
	licenseDataBytes := block.Bytes
	var signedLicense LicenseDataSigned
	json.Unmarshal(licenseDataBytes, &signedLicense)
	hash := sha256.Sum256([]byte(signedLicense.Data))
	signature, err := base64.StdEncoding.DecodeString(signedLicense.Signature)
	if err != nil {
		return nil, err
	}
	err = rsa.VerifyPSS(&clp.PublicKey, crypto.SHA256, hash[:], signature, nil)
	if err != nil {
		return nil, err
	}
	var licenseData LicenseData
	err = fromBase64Json(signedLicense.Data, &licenseData)
	if err != nil {
		return nil, err
	}
	if licenseData.Expires == -1 {
		return &licenseData, nil
	}
	err = clp.TimeVerifier.VerifyTime(licenseData.Expires)
	return &licenseData, err
}
