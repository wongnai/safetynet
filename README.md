# SafetyNet validator

## Usage
Given a [SafetyNet Attestation](https://developer.android.com/training/safetynet/attestation#transfer-response-to-server) 

```go
attestation, err := safetynet.Validate([]byte(safetynetJws))
```

The token is then validated and returned as `attestation`.

It is important that the nonce is validated to be used only once. This is **not** done by this library.

## V1

V1 is available from `go get github.com/wongnai/safetynet`.

V1 only support Google SafetyNet.

## V2

V2 package is available from `go get github.com/wongnai/safetynet/v2`. V2 is *almost* API-compatible with V1, but we accept `string` instead of `[]byte`.

In V2, the returned attestation object contains `attestation.Vendor` field which can be:

- `safetynet.VendorGMS` - [Google SafetyNet](https://developer.android.com/training/safetynet/attestation)
- `safetynet.VendorHMS` - [Huawei Safety Detect](https://developer.huawei.com/consumer/en/doc/development/HMS-Guides/SafetyDetectSysIntegrityDevelopment)
  - HMS does not offer the field `ctsProfileMatch`, instead rely on `basicIntegrity`

Due to custom root required for HMS, V2 does not work on Windows

## License

[MIT License](LICENSE)
