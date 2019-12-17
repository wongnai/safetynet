package safetynet

import (
	"crypto/x509"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

// for mocking
var TimeFunction = time.Now

func ValidateSafetyNet(token []byte) (out Attestation, err error) {
	jwt, err := jwt.ParseSigned(string(token))
	if err != nil {
		return
	}

	if len(jwt.Headers) != 1 {
		err = errorSafetyNetDecode
		return
	}
	key := jwt.Headers[0]

	certs, err := key.Certificates(x509.VerifyOptions{
		DNSName:                   "attest.android.com",
		MaxConstraintComparisions: 5,
		CurrentTime:               TimeFunction(),
	})
	if err != nil {
		return
	}

	err = jwt.Claims(certs[0][0].PublicKey, &out)
	if err != nil {
		return
	}

	if out.Error != "" {
		err = errorSafetyNetError
		return
	}

	return
}
