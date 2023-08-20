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
	// This function will only be called once and the expiration check cycle will stop after it is called.
	// This is mostly meant for applications that run continuously
	// Disabled by default. Set the onexpire function to make the cycle actually work
	OnExpire                func(LicenseData)
	ExpirationCheckInterval time.Duration
	//When this fail count is reached, onexpire is called. Set a higher value for higher leniency.
	AllowedFail int
}

// An interface representing a type that can tell if the given time has passed yet
type TimeVerifier interface {
	VerifyTime(timeNum time.Time) error
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
		PublicKey:               publicKey,
		TimeVerifier:            timeVerifier,
		AllowedFail:             1,
		ExpirationCheckInterval: time.Minute,
		OnExpire:                nil,
	}
}
func (htv httpTimeVerifier) VerifyTime(timeNum time.Time) error {
	resp, err := http.Get(htv.Url)
	if err != nil {
		return err
	}
	date := resp.Header.Get("Date")
	parsed, err := time.Parse(time.RFC1123, date)
	if err != nil {
		return err
	}
	if parsed.After(timeNum) {
		return errors.New("expired license")
	}
	return nil
}

// Checks if a license is signed correctly and not expired
// Returns an error if the license fails to verify
// Start the expiration check cycle
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
	if licenseData.Expires.IsZero() {
		return &licenseData, nil
	}
	err = clp.TimeVerifier.VerifyTime(licenseData.Expires)
	if err != nil {
		return nil, err
	}
	if clp.OnExpire != nil {
		go clp.startExpirationCheckCycle(licenseData)
	}
	return &licenseData, nil
}

func (clp clientLicenseProgram) startExpirationCheckCycle(data LicenseData) {
	failCount := 0
	ticker := time.NewTicker(clp.ExpirationCheckInterval)
	for range ticker.C {
		err := clp.TimeVerifier.VerifyTime(data.Expires)
		if err != nil {
			failCount++
		}
		if failCount >= clp.AllowedFail {
			clp.OnExpire(data)
			return
		}
	}
}
