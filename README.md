# Java Security Library Utils

[![TravisCI Status][travis-image]][travis-url]
[![Codecov Status][codecov-image]][codecov-url]
[![Central OSSRH][oss-nexus-image]][oss-nexus-url]
[![Central Maven][central-image]][central-url]

You can create pub.pem, key.pem and cert.pem with [maven autocert plugin](https://github.com/yadickson/autocert) or with openssl.

## Openssl

```
$ nano openssl.conf
```

### RSA
```
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -sha256 -config openssl.conf -passout pass:Abcd123.,# -nodes
```

### EC
```
$ openssl ecparam -name secp521r1 -genkey -noout -out key1.pem
$ openssl req -new -x509 -sha256 -key key1.pem -out cert.pem -config openssl.conf
$ openssl pkcs8 -topk8 -nocrypt -in key1.pem -out key.pem && rm key1.pem
```

License
-------

GPL-3.0 © [Yadickson Soto](https://github.com/yadickson)

[travis-image]: https://travis-ci.org/yadickson/security-utils.svg?branch=master
[travis-url]: https://travis-ci.org/yadickson/security-utils

[codecov-image]: https://codecov.io/gh/yadickson/security-utils/branch/master/graph/badge.svg?branch=master
[codecov-url]: https://codecov.io/gh/yadickson/security-utils

[oss-nexus-image]: https://img.shields.io/nexus/r/https/oss.sonatype.org/com.github.yadickson/security-utils.svg
[oss-nexus-url]: https://oss.sonatype.org/#nexus-search;quick~security-utils

[central-image]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/security-utils/badge.svg
[central-url]: https://maven-badges.herokuapp.com/maven-central/com.github.yadickson/security-utils
