# Java Security Library Utils

Only for test

**RSA**
```
$ openssl req -x509 -newkey rsa:4096 -keyout src/test/resources/rsa/key.pem -out src/test/resources/rsa/cert.pem -days 365 -sha256 -config src/test/resources/openssl.conf -passout pass:Abcd123.# -nodes
```

**EC**
```
$ openssl ecparam -name secp521r1 -genkey -noout -out src/test/resources/ec/key.pem
$ openssl req -new -x509 -sha256 -key my.key.pem -out src/test/resources/ec/cert.pem -config src/test/resources/openssl.conf
$ openssl pkcs8 -topk8 -nocrypt -in src/test/resources/ec/key.pem -out key.pem && mv key.pem src/test/resources/ec/key.pem
```
