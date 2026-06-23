# SPDX-License-Identifier: LGPL-3.0-or-later
"""Auto-generated channel-binding parity/promotion test vectors.

Each entry is (name, certificate_DER, expected tls-server-end-point). These cover
signature algorithms beyond the default RSA-PKCS1/SHA-256: RSASSA-PSS (whose digest
lives in the signature parameters), DSA, ECDSA-SHA384, and SHA-1 (promoted to
SHA-256 per RFC 5929 4.1). py_scram and truenas_pyscram both equal `expected`.
"""
from base64 import b64decode

CB_VECTORS = [
    ("rsa_pss_sha256", b64decode(
        "MIIDezCCAi+gAwIBAgIUbvFLoNTxKxJMSKWyAwDtovtPfIwwQQYJKoZIhvcNAQEKMDSgDzAN"
        "BglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgMBkxFzAV"
        "BgNVBAMMDnJzYV9wc3Nfc2hhMjU2MB4XDTI2MDYyMjIwNTkzNloXDTM2MDYxOTIwNTkzNlow"
        "GTEXMBUGA1UEAwwOcnNhX3Bzc19zaGEyNTYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK"
        "AoIBAQDpa19BgN87rCwx3j+OkZN2JvpBcM7OQF3O0otYaHePBaGuMYNBApo0PqBp9E1oakm7"
        "ZktqSVpANOp/G4b4+VNIEEi2AO8AUU+hJgw1t2xlLzzxlynstRVVaB3RqYhSdC4HJaBeCC5O"
        "fZ9c14qjzIj6jQANpO/bb2N2aPr5uwSViLiV3MXvN8+g5pXzlSbdRPJyqJdvLgXHA/tS3axR"
        "DHb6P/loIhrE8yaWMJvY1wpp856+WwOu8mVSTwMv0mhScZnJ5BtF3UJJyPjIY8B/VSK189Sj"
        "PidhhXZNk8+1QaHCe4RwuFnMUybGoOmcTBaXJPDErfwt6pGD0ZcjXnW7myUFAgMBAAGjUzBR"
        "MB0GA1UdDgQWBBTuhQOK9oKQhMFCzFx+tYgScnTgHDAfBgNVHSMEGDAWgBTuhQOK9oKQhMFC"
        "zFx+tYgScnTgHDAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUD"
        "BAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCiAwIBIAOCAQEAob7QddtJ12v7"
        "b5RNPSzEP+2GD+1nUGQkOa1lfBzTP0jzvO2f/fgiybKCvZtk/u+PV5fnRsHShgXvhDPzWwzX"
        "BJG6BZ1D/jWfyodoiAOM8RPvA73hIRxtgCtCxGjcC8z2DJi0/GOxNo7RvtGkRwo4JDeG30nA"
        "4UIe8/m2QkO+fHNqBeCUWfi8VGqbXELoGSkL3gWNVHYDWh269GpZBpIu7fw48tuoGxPm7QOV"
        "E2VTAhbvJp3TlFU46ykyp3XdFlGG4+06e5E31/KoFOZH98l3fSw8P4USGoHnUos7XtqnGkTl"
        "Xseuk0DCagMSMiSDsik9pQ9dAk46rg5yZAEzZehC5g=="
    ), bytes.fromhex(
        "a0de0778a5718d214b015d441510876b5b5731bbd622edce1e85be4ad740b250"
    )),
    ("rsa_pss_sha512", b64decode(
        "MIIDezCCAi+gAwIBAgIUI4DhlL/djqOWQrT2Djf/oCZZuP4wQQYJKoZIhvcNAQEKMDSgDzAN"
        "BglghkgBZQMEAgMFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgMFAKIDAgFAMBkxFzAV"
        "BgNVBAMMDnJzYV9wc3Nfc2hhNTEyMB4XDTI2MDYyMjIwNTkzNloXDTM2MDYxOTIwNTkzNlow"
        "GTEXMBUGA1UEAwwOcnNhX3Bzc19zaGE1MTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK"
        "AoIBAQCvn0EEVFvC+1YpBcs9pshNI/3RQueSeG4TrOOccthZWQSpal7nuXNgjYHuRcnASykr"
        "0QUcdkNnWkrejILE0o3yHNc3jrEFGkVW2nhuG6rRTcRmqzCL9CQ4n5DH3tyilnwLDZXZ0Xdu"
        "xcMPnj8QR45pZIfMxY7x8BXItTjfTFR3Ym7a+zeGLGwj+xYsPeOGlCPO7TsPaYySM8ZyS4ak"
        "PN39A3xMHJuH8d3hIDm0oNBA78hqxF0tx8UK8UY2KPOucehwIQYZ9HFyWo5NxbX23a3mfXe6"
        "MHoOD+6y1nD80YFStK8aUlU6JrrcDDnVO7QzPGnx6njc0HAlYM3V/XuvHny5AgMBAAGjUzBR"
        "MB0GA1UdDgQWBBSbk4AXUwNJhOrmzv9NMmq5CIeWPDAfBgNVHSMEGDAWgBSbk4AXUwNJhOrm"
        "zv9NMmq5CIeWPDAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0oA8wDQYJYIZIAWUD"
        "BAIDBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIDBQCiAwIBQAOCAQEAR1emzB16GHIL"
        "xWiTq7kAirHxYlh80phTMRv0AarLDNavW0ZptncQlh2EeyzsUEknokIjqvpL9r+NrLWa+iIr"
        "+3J8ZaWiiBLdGEmENebMnM1OGnCQB9yBwneyoLEFZiPNFDM6S2/uSbyM0ir1P95zi51MYBAE"
        "pQ3YWjAtXB1CgrIjOJ2b08CkJVy3uyKk7CiDRmDXFsM6pVC0cI4yso9a8/wrhxmO4Evq2v8o"
        "hXyduSqu1BNUTg3NvDGwwlU9Uik/hp5iV/P47mhONfv+hZP/cCdnCNzJT2V7dB3+h7wQUBmC"
        "UKWiFtC03S7iR8d2+Pxrd9WShBydRU8gHDqjG1ZwHw=="
    ), bytes.fromhex(
        "4b2eb9c0b129e10c0a09b29a4d670062efd0da53be232a54b65b0c4a0f193e3a"
        "133d79cb8f569681e3bc131dae654bd5f8a34b7215a18d42bae6343313bdabe8"
    )),
    ("ecdsa_sha384", b64decode(
        "MIIBwTCCAUagAwIBAgIUf+oUEWmBYwffug4hBlnRAtFdejQwCgYIKoZIzj0EAwMwFzEVMBMG"
        "A1UEAwwMZWNkc2Ffc2hhMzg0MB4XDTI2MDYyMjIwNTkzNloXDTM2MDYxOTIwNTkzNlowFzEV"
        "MBMGA1UEAwwMZWNkc2Ffc2hhMzg0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQXRbllZNtIe8"
        "nEqVC0Pnv9XrtYuK3JjTX8h8+sd5yZtXoKoXvTZA3s8oRyTp+Ua9Y/154OqiDufPBpiVJVa1"
        "v28xiw9d2AiWa19VxyTQTTyrHofUnXb0VWWFQAi+UFMQo1MwUTAdBgNVHQ4EFgQUeRKlokr7"
        "DgnFjJdRNzpPunHBb0MwHwYDVR0jBBgwFoAUeRKlokr7DgnFjJdRNzpPunHBb0MwDwYDVR0T"
        "AQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA9/opjXvE22x675TqsjWogAbJJMe9tAJG"
        "I7RoMiGWaRO3Jam06Ik64/nAXn7tDLP4AjEAryelYXb9DOOS6sanz4D+puRLU4CdiNlA89iT"
        "WTjtkH7w+ctmj8jKXNBeLKdbrCEL"
    ), bytes.fromhex(
        "a16feae6f8a8e471fcd17c797a3d9357f3df17e16e3f2e30da1bb92d81723f7faebf9e29c7cdb73b4755e781e433d785"
    )),
    ("rsa_sha1", b64decode(
        "MIIDBzCCAe+gAwIBAgIUPJQDMd+Kp0m5FxshY+PfE0Z47fIwDQYJKoZIhvcNAQEFBQAwEzER"
        "MA8GA1UEAwwIcnNhX3NoYTEwHhcNMjYwNjIyMjA1OTM2WhcNMzYwNjE5MjA1OTM2WjATMREw"
        "DwYDVQQDDAhyc2Ffc2hhMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkVoiEJ"
        "x7ANcSzCThZSdu/oXYQf4bYpvFGH7xa+23l7Kbei9KBSCcB12HWSGeQb+bik9OU7fIC5DWMH"
        "H0nolgNIwclebPORL+6tUYA+xxqIN0dXsjMcD7J9MR6KLX8YcwlnmCjPw9qOTRrmXiUsqWsE"
        "jwytsqxuMvTMUnJG2gNJNLyuCabBWHVzPWXoVKBT7j6b93RSSl1Z4GhN7gpfLmSVQPaJ0Iw5"
        "2hTOgj5pffPIKVx6Se4diS8Wp/9QReFO2tZW7ccFcwCUeml72CJlp8zgFanfuwdeVRJF1DEn"
        "eKKo/egmONTWG074shpnFB1jdgqxXRXAcaztNZ2i0k+L3ZECAwEAAaNTMFEwHQYDVR0OBBYE"
        "FHSiQey2fSDnEc20AkTScG71uDsHMB8GA1UdIwQYMBaAFHSiQey2fSDnEc20AkTScG71uDsH"
        "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAHI8I9RBh0FBX3Oi3U1vQCwC"
        "JG2NrKiA73FoqohUxXVCq6JUojG8l484uJHw2P2zaUTaai1vdG+zKmwbX235uitxXtQ8oY9b"
        "juIQjBsUwyikldSsZVE30EFmKUXIvhWDssvI6pU/t+jINuac1Ht/zMkz0aAzVrLwaAMrNbtU"
        "DUaB4BMtGaC+TNMzALBYiD51dfPlRbDZKqc7l2zhXXyu+WoaIsK+pVqTA69aTdO0pYNBt34c"
        "dq/lzuj/eU27A96MOIRMrGE4VB9yc1phkUfEWmSWNEglREOnYWMWm466z4E6jbAjb5zJGMev"
        "iAvEGMy6pUKgTRW7FEVxvFtDUDjL5pw="
    ), bytes.fromhex(
        "9cf8083887b586b8aa1b511190141c824e73fd09eac93f0945c0199080023710"
    )),
    ("dsa_sha256", b64decode(
        "MIIEZzCCBBOgAwIBAgIUZRfnSemmaQReHYhIXH/LT3EEQdgwCwYJYIZIAWUDBAMCMBUxEzAR"
        "BgNVBAMMCmRzYV9zaGEyNTYwHhcNMjYwNjIyMjA1OTM2WhcNMzYwNjE5MjA1OTM2WjAVMRMw"
        "EQYDVQQDDApkc2Ffc2hhMjU2MIIDRDCCAjYGByqGSM44BAEwggIpAoIBAQCJo/kAk+fYjTtW"
        "oDagfPciNzvMIQnY/y+rBu+jzMMjPA0/gsSNlI1ixGYdSwMGee8ZpI+VIlK6FynXPJgeCVmJ"
        "SxTVoXGT+AdSoWbhw7q9CDlqPeUb431rOplUL5O0pklZHVcznl7q3EvvhNLaJ1iMXDvE1nsm"
        "LlnKxdQYdA7j69vgZCawyGMl6UwP5deox8/MLcdvgK49p4ryI43rzAS+17KhlftXKt+KZktI"
        "RIdhacOimJZgfy6oELEh4z6FlF3SXGqv5tWpWlpnSKQcDDVXG9CRmcU16zNc9MkJTsrZcDMh"
        "BGSkDW8jAK/bd6E9YuqZ9nB6gNN3d+XzhW5sN6gZAh0A41ap4k32+1Cj0CIMKLVFXWCd8562"
        "FUZhRHuZIQKCAQEAiZ387IoEmYZX/8U5tR1aczxDkVcy8wgyOvhobXhj/aMD6q84KK6I2mlx"
        "AyLxpC5sZBUiu7h+Mkftb0gqWZFwtQiczuawuQET0YhoqeuAOniGyZryZEGZeuG5BgTb9eaW"
        "7a3D2fYm50hfFhFKSlnZAJR2ZNFZNaxOoYraeCSqVukbBwmLQgbr95YKPTX3puwzf5gY7I6e"
        "u15mXgZpVcy5wrZ1pxRyLLYQPoCoI3bzOHoqgmnJmykWFzPObRWJiZlpkQLQ3O9T8LR6Wqmi"
        "jhdWpYDcPchNbWVOq37Mpl7OrVottTy+pYoYjwM+j32hH5iequWDgdcw/cDpd+FH7i4LVgOC"
        "AQYAAoIBAQCIc1x0JSROUVfeDr0nIbqgZIN6zMg7YCC9mJMdQcIiSahnSaHOJzRtGapcN6Ta"
        "HfY3zApx53JMU81gwWzWYCJcWs2gbjaLHSlm3lDNyPTRgzuWWKvyvKHvL7TGRfNnOS/VrvzO"
        "/hxA2w1fpTWBcn5tIJQk1ri2yWxUJUQ52/t7WojUgen14Bi2qeITvELmwXFnuSs8UhsRwal1"
        "2fxMC/fdnh4jR8gBfvirlH0vvRB4ZrOIhU+ZwjwebZKNFdH9IJcvMcz3XnYA8FvP3R99VWkx"
        "JubCeWVlNJZzUCs7L5C0+cPBPkPce9sOrS3iqHMpk4J62JjM/CEgSBJ3VDNvh3iXo1MwUTAd"
        "BgNVHQ4EFgQUzVmJizDr+Rth2910JRdW45fV6XkwHwYDVR0jBBgwFoAUzVmJizDr+Rth2910"
        "JRdW45fV6XkwDwYDVR0TAQH/BAUwAwEB/zALBglghkgBZQMEAwIDQQAwPgIdANTFiRLd6oV6"
        "mknToIBJjTAp9csMwFRPsF+nS9ACHQC24O9iRcqXU+rta7ocM6SDhSiDn1KZapUIAqHU"
    ), bytes.fromhex(
        "6e19e230f917fd3922f39fff90a263f1df618fd4d8080037f75f1b32f97b0e27"
    )),
]

# Signature algorithms with no single well-defined hash: rejected by both
# py_scram and truenas_pyscram (RFC 5929 4.1 -> undefined).
REJECTED_VECTORS = [
    ("ed25519", b64decode(
        "MIIBODCB66ADAgECAhRF/i2VZfabTYtGC96jEmDKQWs7HzAFBgMrZXAwEjEQMA4GA1UEAwwH"
        "ZWQyNTUxOTAeFw0yNjA2MjIyMDU5MzZaFw0zNjA2MTkyMDU5MzZaMBIxEDAOBgNVBAMMB2Vk"
        "MjU1MTkwKjAFBgMrZXADIQBG6mG6PIveRZbDEpUA0h2+zqcfkFflhjFU6WMltek8H6NTMFEw"
        "HQYDVR0OBBYEFI0SqZaciNfleT/XktQEcIjga8GhMB8GA1UdIwQYMBaAFI0SqZaciNfleT/X"
        "ktQEcIjga8GhMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EAMvh4cKf/RBo2Pa9xlyAI1PxL"
        "R43eNEd6siuiayO5lojZy92QlmHI3Y1SEF7RQd6E9PeKsGmdo/Pcpu75xrfTDw=="
    )),
]
