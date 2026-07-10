## INWX provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [INWX](https://www.inwx.com/) DNS via the [DOMRobot XML-RPC API](https://www.inwx.com/en/help/apidoc).

### Installation

#### Command line

```
pip install octodns-inwx
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==1.18.0
octodns-inwx==0.1.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/fjaeckel/octodns-inwx.git@<sha>#egg=octodns_inwx
```

### Configuration

```yaml
providers:
  inwx:
    class: octodns_inwx.INWXProvider
    # INWX account username (required)
    username: env/INWX_USERNAME
    # INWX API password (required)
    api_password: env/INWX_PASSWORD
    # API endpoint base URL (optional, defaults to the production endpoint)
    #endpoint: https://api.domrobot.com
```

A dedicated API user with permission to manage the affected domains is recommended.

### Support Information

#### Records

INWXProvider supports A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TLSA, and TXT.

PTR records are managed the same way as any other record type, so reverse
DNS zones (e.g. `2.0.192.in-addr.arpa.` or `...ip6.arpa.`) can be managed by
octoDNS as long as the corresponding reverse zone is registered with INWX.

#### Dynamic

INWXProvider does not support dynamic records.

### Development

Install the package in editable mode along with the development tools:

```
pip install -r requirements-dev.txt
```

Tests are run with:

```
python -m unittest discover -s tests -v
```

Linting is run with:

```
ruff check .
```

### Releasing

Releases are published to PyPI automatically by [.github/workflows/publish.yml](.github/workflows/publish.yml)
whenever a `v*` tag is pushed. The workflow refuses to publish if the tag
doesn't match the version in `pyproject.toml`, so the two must be bumped
together:

1. Update `version` in [pyproject.toml](pyproject.toml) (e.g. `0.1.2` -> `0.1.3`).
2. Commit the bump, e.g. `git commit -am "Bump version to 0.1.3"`.
3. Tag the commit to match, with a `v` prefix: `git tag v0.1.3`.
4. Push both the commit and the tag: `git push && git push origin v0.1.3`.

Pushing the tag triggers the workflow, which verifies the tag matches
`pyproject.toml`, builds the sdist/wheel, and publishes to PyPI via trusted
publishing (no manual credentials needed).

