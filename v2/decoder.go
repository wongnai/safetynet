package safetynet

import (
	"crypto/x509"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

// for mocking
var TimeFunction = time.Now

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

	var cert *x509.Certificate
	var foundVendor Vendor

	for _, vendor := range AllVendors {
		var certs [][]*x509.Certificate
		certs, err = key.Certificates(x509.VerifyOptions{
			DNSName:                   string(vendor),
			Roots:                     roots,
			MaxConstraintComparisions: 5,
			CurrentTime:               TimeFunction(),
		})
		if err == nil {
			foundVendor = vendor
			cert = certs[0][0]
			break
		}
	}
	if cert == nil && err != nil {
		return
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
