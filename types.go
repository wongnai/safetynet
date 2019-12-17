package safetynet

import (
	"errors"
	"time"
)

var ErrorSafetyNetDecode = errors.New("cannot decode token")
var ErrorBasicIntegrity = errors.New("basic integrity check fail")
var ErrorSafetyNetError = errors.New("safetyNet report error")

type Attestation struct {
	Timestamp                  int64    `json:"timestampMs"`
	Nonce                      string   `json:"nonce"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkDigestSHA256            string   `json:"apkDigestSha256"`
	ApkCertificateDigestSHA256 []string `json:"apkCertificateDigestSha256"`
	CTSProfileMatch            bool     `json:"ctsProfileMatch"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
	Advice                     string   `json:"advice,omitempty"`
	Error                      string   `json:"error,omitempty"`
}

func (s Attestation) GetTimestamp() time.Time {
	return time.Unix(s.Timestamp/1000, (s.Timestamp%1000)*int64(time.Millisecond))
}
