# octodns-inwx

First-class [octoDNS](https://github.com/octodns/octodns) provider for INWX DNS.

## Installation

```sh
pip install octodns-inwx
```

## Configuration

```yaml
providers:
  inwx:
    class: octodns_inwx.INWXProvider
    username: env/INWX_USERNAME
    password: env/INWX_PASSWORD
```