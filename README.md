# lorica

lorica implements a certification authority (CA) that leverages hardware
security module (HSM).

## SoftHSM2

[SoftHSM2] is required for running the test suite. The use running the
test suite should have access to `softhsm2-util` command and the PKCS#11
module should be available at `/usr/lib/softhsm/libsofthsm2.so`.

[SoftHSM2]: https://github.com/opendnssec/SoftHSMv2
