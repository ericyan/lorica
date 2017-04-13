# lorica

lorica implements a certification authority (CA) that leverages hardware
security module (HSM).

## Run tests with SoftHSM2

The test suite expects a [SoftHSM2] token labeled `lorica_test` present
and that token should be initialized with user PIN `123456`.

Such token can be created by the following command:

```
softhsm2-util --init-token --free --label lorica_test --so-pin lorica --pin 123456
```

To delete the token:

```
softhsm2-util --delete-token --token lorica_test
```

[SoftHSM2]: https://github.com/opendnssec/SoftHSMv2
