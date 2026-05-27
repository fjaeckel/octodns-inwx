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

INWXProvider supports A, AAAA, CAA, CNAME, MX, NS, SRV, and TXT.

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
