# artanis-custody

This is a plugin for [GNU Artanis](https://artanis.dev) that provides a warm wallet for custody of funds.

![alt text](http://artanis.dev/img/artanis-custody.png)

## Dependencies

- [GNU Guile](https://www.gnu.org/software/guile/)
- [GNU Artanis](https://artanis.dev)
- [Guile JWT](https://github.com/aconchillo/guile-jwt)
- [Guile gcrypt](https://notabug.org/cwebber/guile-gcrypt)

## Installation

```sh
sudo make install
```

## TODO

- Cryptocurrency exchange
  - Coinbase
    - [x] Complete Coinbase API
    - [x] Coinbase advanced authentication with JWT
  - Quicknode
    - [ ] Complete Quicknode API
    - [ ] Quicknode authentication

- Secure credentials management
  - [ ] TEE support
  - [ ] Secure enclave credentials storage
  - [ ] Secure enclave transaction signing
  - [ ] Secure enclave access for FUSE filesystem

- Security best practices
  - [ ] Security enhancements based on [HardenedLinux](https://hardenedlinux.org)
  - [ ] Linux kernel vaccine script based on [VED](https://github.com/hardenedlinux/ved)
  - [ ] Secure enclave credentials management

## Developer

[HardenedLinux community](https://hardenedlinux.org)

## License

GPLv3

## For fun and profit
