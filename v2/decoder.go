package safetynet

import (
	"crypto/x509"
	"errors"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

// for mocking
var TimeFunction = time.Now

var ErrUnknownVendor = errors.New("safetynet: valid certificate found but not from any known safetynet vendors")

var roots, _ = x509.SystemCertPool()

func init() {
	addHmsRoot(roots)
}

func Validate(token string) (out Attestation, err error) {
	rawToken := token
	token = preprocessHms(token)

	jwt, err := jwt.ParseSigned(token)
	if err != nil {
		return
	}

	if len(jwt.Headers) != 1 {
		err = ErrorSafetyNetDecode
		return
	}
	key := jwt.Headers[0]

	var certs [][]*x509.Certificate
	certs, err = key.Certificates(x509.VerifyOptions{
		Roots:                     roots,
		MaxConstraintComparisions: 5,
		CurrentTime:               TimeFunction(),
	})
	if err != nil {
		return
	}

	cert := certs[0][0]
	var foundVendor Vendor
	// validate cert name here as HMS use common name
	for _, vendor := range AllVendors {
		// go 1.15 no longer validate common name, which HMS uses
		if cert.VerifyHostname(string(vendor)) == nil || cert.Subject.CommonName == string(vendor) {
			foundVendor = vendor
			break
		}
	}
	if foundVendor == "" {
		return Attestation{}, ErrUnknownVendor
	}

	if foundVendor == VendorHMS {
		// huawei botched their jwt signing - validate it ourselves
		err = validateHmsSigning(rawToken, jwt, cert)
		if err != nil {
			return
		}

		err = jwt.UnsafeClaimsWithoutVerification(&out)
		if err != nil {
			return
		}
	} else {
		err = jwt.Claims(cert.PublicKey, &out)
		if err != nil {
			return
		}
	}

	if out.Error != "" {
		err = ErrorSafetyNetError
		return
	}

	out.Vendor = foundVendor

	return
}
