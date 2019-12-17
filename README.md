# SafetyNet validator

## Usage
Given a [SafetyNet Attestation](https://developer.android.com/training/safetynet/attestation#transfer-response-to-server) 

```go
attestation, err := safetynet.Validate([]byte(safetynetJws))
```

The token is then validated and returned as `attestation`.

It is important that the nonce is validated to be used only once. This is **not** done by this library.

## License

[MIT License](LICENSE)
