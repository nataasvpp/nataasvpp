# vCDP

## clone and build VPP

```bash
git clone https://git.fd.io/vpp
cd vpp
make install-deps
make install-ext-deps
make build build-release
```

## Clone vCDP

```bash
cd ..
git clone <this repo URL>
cd vcdp
```

## run
```bash
make install run
```

or release version

```bash
make install-release run-release
```
