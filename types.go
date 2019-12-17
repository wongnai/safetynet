package safetynet

import (
	"errors"
	"time"
)

var errorSafetyNetDecode = errors.New("Cannot decode token")
var errorBasicIntegrity = errors.New("Basic integrity check fail")
var errorSafetyNetError = errors.New("SafetyNet report error")

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
