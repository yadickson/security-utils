/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.certificate;

import com.github.yadickson.security.exception.CertificateException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.After;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

/**
 *
 * @author Yadickson Soto
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateManagerTest {

    @InjectMocks
    private CertificateManagerImpl manager;

    private InputStream stream;

    @Before
    public void before() {
        stream = null;
    }

    @After
    public void after() throws Exception {
        if (stream != null) {
            stream.close();
        }
    }

    @Test(expected = CertificateException.class)
    public void testGetterPublicKeytreamNull() throws CertificateException {
        manager.getPublicKey(stream);
    }

    @Test(expected = CertificateException.class)
    public void testGetterPublicKeyError() throws CertificateException {

        String content = "-----BEGIN CERTIFICATE-----\n"
                + "MIIFezCCA2MCFFYg+fL6pEIzQITgJdSXOAGwNwDxMA0GCSqGSIb3DQEBCwUAMHox\n"
                + "CzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xpdGFuYTERMA8G\n"
                + "A1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYDVQQLDARMVERB\n"
                + "MRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDAeFw0xOTA1MDMyMDUxNDVaFw0yMDA1\n"
                + "MDIyMDUxNDVaMHoxCzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9w\n"
                + "b2xpdGFuYTERMA8GA1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0w\n"
                + "CwYDVQQLDARMVERBMRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDCCAiIwDQYJKoZI\n"
                + "hvcNAQEBBQADggIPADCCAgoCggIBANOC1ZRKYZvSrsGlf770NldCiG3qMP0xxCJD\n"
                + "OcIbObV60yhcgdT/YO0GI0t3yuFIObUCr9mae28OIkJ5ppXvEMGzccMyE1lG74wX\n"
                + "b12hg8h5SYH6S5anrT/0ygGy/qmkbBTI9WaSPZPgvhiBKjfGAFty0w7P9cOzAupf\n"
                + "8j81sRlZhkIGX7n39WcU6vkuh9jCnmQd86c+SnSmgI9aL8vdlOlXasGlkIaiEx3S\n"
                + "+QboOU6LAR1ifj3aFv+NhornoBMlTIYWsWMCywDVA0y5tY9Hrmw7Wiv38kp7g/y3\n"
                + "ZRCODWKDgmc/bexTv6FNfj2/vi1mzuN8dwLtmPurUPQTdf/8aB3bLQhnr3x0AD5F\n"
                + "................................................................\n"
                + "9GqtqpmZ9qAicpwtX5xHqtCDaMxA8hi8di1PKpeuasLGQg9bhsglitrpauvgeoOg\n"
                + "cLLtj5Xv9o+2vikOoD+91wscQizsx3XEsNCn0FvrMm+8VYy2Lwpo0bTN5dBhKZH6\n"
                + "IQJI6spHMtgLTs8gAXVeoJGpUrcTH1Ys81uUTiokW2shcFWCs+PMldHtIKC7h3L1\n"
                + "UaGKLFpozSpbdjx24pZO5Uz7h5pwgxwYJBEAXOlZRCZoTv0b10Ci6q/2Edw8slZk\n"
                + "EfjNxk57AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAF4X27RMqQ3znGzKqHyBx8RH\n"
                + "x4htuf4W1B6ft6nLBco1SI3c9D/fPlDN7SeKgC1Ko4Gv4k3Qm+c5g0gQeJC9fd22\n"
                + "PO+YRyzSJkQbriwkOzUd2786MP3ReWDVbV9nT1vg/B2U87ZaDg9/CrO99Z1d3Zkc\n"
                + "o79kBWpb8Nkypr9Ia+TcXt+NPdJdz2bekK8TKan7EfEHHX2RBtKjg8615emlgw6D\n"
                + "kpLsoDGK+9Dt+V4yJ0YzLSDoQGhsT5qpikP4GHwOddMfMrLZpGFv1qLjr4OHljIg\n"
                + "Od9tyflNOzyGCJZ7ca5d0F0vsHJFoZFhtgVao+lxirkDYdyEi4NfDuB9XCWYnscu\n"
                + "vVEL+5QelMhUkptpyCdN6ny2IBeo+NG3UPlty2JcZMoQNh04/y9F48kdPjMt931z\n"
                + "ftBCLs0a5+P79r256VHguHVN4ZlmRg0kvh73OZ6i+6FbKZ1xkIHNA/I50OFj686v\n"
                + "f/LHcPyQiyc9rIHUebQMtcEjrZNG8a2G5idq/Fi0637KP02t1vjBI0f8JNpflvCi\n"
                + "VFdjRfESznpZwkqWHnTtNMY/5GKnkT831fWbJCUBHkc7Ru+dQ/BQiagQccYyy/zM\n"
                + "1Q+dtoDQ99PZuu5b/OWidUPQYzRWSaV/Tb/7FKUxT0IyVSwZlf3V4gygpWrZKh6k\n"
                + "j3bts5oYUj0EyswNGtwI\n"
                + "-----END CERTIFICATE-----";

        stream = new ByteArrayInputStream(content.getBytes());
        manager.getPublicKey(stream);
    }

    @Test
    public void testGetterPublicKeyOk() throws CertificateException {

        String content = "-----BEGIN CERTIFICATE-----\n"
                + "MIIFezCCA2MCFFYg+fL6pEIzQITgJdSXOAGwNwDxMA0GCSqGSIb3DQEBCwUAMHox\n"
                + "CzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xpdGFuYTERMA8G\n"
                + "A1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYDVQQLDARMVERB\n"
                + "MRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDAeFw0xOTA1MDMyMDUxNDVaFw0yMDA1\n"
                + "MDIyMDUxNDVaMHoxCzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9w\n"
                + "b2xpdGFuYTERMA8GA1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0w\n"
                + "CwYDVQQLDARMVERBMRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDCCAiIwDQYJKoZI\n"
                + "hvcNAQEBBQADggIPADCCAgoCggIBANOC1ZRKYZvSrsGlf770NldCiG3qMP0xxCJD\n"
                + "OcIbObV60yhcgdT/YO0GI0t3yuFIObUCr9mae28OIkJ5ppXvEMGzccMyE1lG74wX\n"
                + "b12hg8h5SYH6S5anrT/0ygGy/qmkbBTI9WaSPZPgvhiBKjfGAFty0w7P9cOzAupf\n"
                + "8j81sRlZhkIGX7n39WcU6vkuh9jCnmQd86c+SnSmgI9aL8vdlOlXasGlkIaiEx3S\n"
                + "+QboOU6LAR1ifj3aFv+NhornoBMlTIYWsWMCywDVA0y5tY9Hrmw7Wiv38kp7g/y3\n"
                + "ZRCODWKDgmc/bexTv6FNfj2/vi1mzuN8dwLtmPurUPQTdf/8aB3bLQhnr3x0AD5F\n"
                + "wRBLLMKh4OEk3MqmsF6yrnBuUsxLNlQ+dTEq2AmRAoVGhHO6LxaSeoRk5jY+RbnZ\n"
                + "9GqtqpmZ9qAicpwtX5xHqtCDaMxA8hi8di1PKpeuasLGQg9bhsglitrpauvgeoOg\n"
                + "cLLtj5Xv9o+2vikOoD+91wscQizsx3XEsNCn0FvrMm+8VYy2Lwpo0bTN5dBhKZH6\n"
                + "IQJI6spHMtgLTs8gAXVeoJGpUrcTH1Ys81uUTiokW2shcFWCs+PMldHtIKC7h3L1\n"
                + "UaGKLFpozSpbdjx24pZO5Uz7h5pwgxwYJBEAXOlZRCZoTv0b10Ci6q/2Edw8slZk\n"
                + "EfjNxk57AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAF4X27RMqQ3znGzKqHyBx8RH\n"
                + "x4htuf4W1B6ft6nLBco1SI3c9D/fPlDN7SeKgC1Ko4Gv4k3Qm+c5g0gQeJC9fd22\n"
                + "PO+YRyzSJkQbriwkOzUd2786MP3ReWDVbV9nT1vg/B2U87ZaDg9/CrO99Z1d3Zkc\n"
                + "o79kBWpb8Nkypr9Ia+TcXt+NPdJdz2bekK8TKan7EfEHHX2RBtKjg8615emlgw6D\n"
                + "kpLsoDGK+9Dt+V4yJ0YzLSDoQGhsT5qpikP4GHwOddMfMrLZpGFv1qLjr4OHljIg\n"
                + "Od9tyflNOzyGCJZ7ca5d0F0vsHJFoZFhtgVao+lxirkDYdyEi4NfDuB9XCWYnscu\n"
                + "vVEL+5QelMhUkptpyCdN6ny2IBeo+NG3UPlty2JcZMoQNh04/y9F48kdPjMt931z\n"
                + "ftBCLs0a5+P79r256VHguHVN4ZlmRg0kvh73OZ6i+6FbKZ1xkIHNA/I50OFj686v\n"
                + "f/LHcPyQiyc9rIHUebQMtcEjrZNG8a2G5idq/Fi0637KP02t1vjBI0f8JNpflvCi\n"
                + "VFdjRfESznpZwkqWHnTtNMY/5GKnkT831fWbJCUBHkc7Ru+dQ/BQiagQccYyy/zM\n"
                + "1Q+dtoDQ99PZuu5b/OWidUPQYzRWSaV/Tb/7FKUxT0IyVSwZlf3V4gygpWrZKh6k\n"
                + "j3bts5oYUj0EyswNGtwI\n"
                + "-----END CERTIFICATE-----";

        stream = new ByteArrayInputStream(content.getBytes());
        PublicKey result = manager.getPublicKey(stream);

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testGetterPublicKeyOk2() throws CertificateException {

        String content = "-----BEGIN CERTIFICATE-----\n"
                + "MIICHzCCAcmgAwIBAgIJAO+ifChoA8pCMA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNV\n"
                + "BAYTAkNMMREwDwYDVQQIDAhTYW50aWFnbzERMA8GA1UEBwwIU2FudGlhZ28xFzAV\n"
                + "BgNVBAoMDkJhbmNvIGRlIENoaWxlMR0wGwYDVQQLDBRQbGF0YWZvcm1hIENvbWVy\n"
                + "Y2lhbDAeFw0xNTA5MDgyMDE1NTVaFw0xNjA5MDcyMDE1NTVaMGsxCzAJBgNVBAYT\n"
                + "AkNMMREwDwYDVQQIDAhTYW50aWFnbzERMA8GA1UEBwwIU2FudGlhZ28xFzAVBgNV\n"
                + "BAoMDkJhbmNvIGRlIENoaWxlMR0wGwYDVQQLDBRQbGF0YWZvcm1hIENvbWVyY2lh\n"
                + "bDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvveaWr5a/0AF2o0WC4YU39DE8vMZT\n"
                + "dXWaFRX0SFGtCh/n3x14SuiqSaZe33haaiUpRlvmv8++4ZYpmJDTFM/nAgMBAAGj\n"
                + "UDBOMB0GA1UdDgQWBBTtIwjvgoL7b0A2b6W6hAFnnZohJDAfBgNVHSMEGDAWgBTt\n"
                + "IwjvgoL7b0A2b6W6hAFnnZohJDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA\n"
                + "A0EAmEjnRh72d864WRAaywNdwdVWc1G57osBp8cdB95/AJWA+Ac8/BllnaDKpfqY\n"
                + "uVs3hC28bRwxwxGJ+j5iJvlOrQ==\n"
                + "-----END CERTIFICATE-----";

        stream = new ByteArrayInputStream(content.getBytes());
        PublicKey result = manager.getPublicKey(stream);

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test(expected = CertificateException.class)
    public void testGetterPrivateKeyStreamNull() throws CertificateException {
        manager.getPrivateKey(stream, "RSA");
    }

    @Test(expected = CertificateException.class)
    public void testGetterPrivateKeyEntradaError() throws CertificateException {

        String content = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDTgtWUSmGb0q7B\n"
                + "pX++9DZXQoht6jD9McQiQznCGzm1etMoXIHU/2DtBiNLd8rhSDm1Aq/ZmntvDiJC\n"
                + "eaaV7xDBs3HDMhNZRu+MF29doYPIeUmB+kuWp60/9MoBsv6ppGwUyPVmkj2T4L4Y\n"
                + "gSo3xgBbctMOz/XDswLqX/I/NbEZWYZCBl+59/VnFOr5LofYwp5kHfOnPkp0poCP\n"
                + "Wi/L3ZTpV2rBpZCGohMd0vkG6DlOiwEdYn492hb/jYaK56ATJUyGFrFjAssA1QNM\n"
                + "ubWPR65sO1or9/JKe4P8t2UQjg1ig4JnP23sU7+hTX49v74tZs7jfHcC7Zj7q1D0\n"
                + "E3X//Ggd2y0IZ698dAA+RcEQSyzCoeDhJNzKprBesq5wblLMSzZUPnUxKtgJkQKF\n"
                + "RoRzui8WknqEZOY2PkW52fRqraqZmfagInKcLV+cR6rQg2jMQPIYvHYtTyqXrmrC\n"
                + "xkIPW4bIJYra6Wrr4HqDoHCy7Y+V7/aPtr4pDqA/vdcLHEIs7Md1xLDQp9Bb6zJv\n"
                + "vFWMti8KaNG0zeXQYSmR+iECSOrKRzLYC07PIAF1XqCRqVK3Ex9WLPNblE4qJFtr\n"
                + "................................................................\n"
                + "aE79G9dAouqv9hHcPLJWZBH4zcZOewIDAQABAoICAFZScE5sKPgKfS4lGETbsI3e\n"
                + "ZoXNbZ74P57oJtt0dxH9Bc7UKly+uVUjCyaSxmc5LewVI6XAqZ3Ce/L7aSSKBCG5\n"
                + "1bUfa8wk6kEXk2j4MSuRbJGykET1O/z9L7CP1+VuaHn3JkhtaNpAf/TKSmum0KCB\n"
                + "9Wd3MktjdM4oyFpJ1HSPF/88ULc6XppqbBe0iNbLXw9nNfjMsGB5T8Cxww4F6e9t\n"
                + "sPFFW/3GidzDLMVH45ONoa/XccRWjMpRfVaVf7wwndGf01egXS+CwC0BIftO+v3L\n"
                + "H1sQf38sd8qdIo8mGopZN9Bhj8BC0dPIJ7yV08z9x3QKaRv10ljsK0bh5mfKIMdI\n"
                + "qxUvEfIogFqpmNZJj2avB4KR7kH69Z5FXeDj9bSqPfbyymXhTviDlXmWYUMOeboI\n"
                + "1WxV5gF8vz5xDQWE5isA3X5WEXxHhtsfu55NG14biO+3CSiC703G0whEVCUJwT/W\n"
                + "tV7us8M2JEJ66bAVYN4OkpDx7sumYsaatGuLnH9NuBfiUf5F1mri8ObOF8h8hhS7\n"
                + "kAmbAwa3nMH1O8Yc7D9uz5yuFJx7Tyh6zhMvCVb8VFUW4TuGkY0G2GTrD+QT6+8N\n"
                + "3rQSHNv9u6BNXb2LfajH0x4c6ASRnTe80NbTWHv7jVMY4qjnauvW8wS5MK5cKkQE\n"
                + "QWltm+EwLDTgKa27hcqRAoIBAQDpOnpeh/Gx3bMeq2SvdnZOQyxvDSnZ6o22UdZ9\n"
                + "8jlwh8X1bXQXaWXnKblAcDXwAyaTjZLzA0kijTUORL0AILo8q3kanB4joIdbFHEm\n"
                + "L6JKv13SyJ8Gs60HA06miE2VBCeOjQGmDt4bNGBdIYeBt6GdtdDqgsyfIjYFV6Fy\n"
                + "ErAgKxf83N/Urp5Ep8tOamEfewgfyfYCwgkAZ/01mqjN+30aeSzEkPdXUSoli6MU\n"
                + "YZwb6QfLH89gxkGvh9/azwfSunvi5ZSwgvGnLJ25gTwwyGhL+tAnollEDRQUPLX2\n"
                + "Ul5wTgGo/vzinVOyZNBtGaj37V1HYThvpMsVI/Gdf1EpxMkZAoIBAQDoKYh0TWwq\n"
                + "I9ChV4pL+koVNc4eD9UVyRF+32rl8tMdlAq2eSQS9H5oPJMiVaf3F1hTYwB6ZFWS\n"
                + "A24x/2Gz5ZWZYGh5DpEEgAe9MYVTdsCX+qtel0m7xSdy4R8Updhr+U3Y9D4fleI0\n"
                + "HPdZSHXTrn9bgJR9CuMZoBUsO2XMOFxcShPFuTF135GDtF2OEAOC4qp5JY7QEosy\n"
                + "qp1LsP7OTkXS0DRWoH4JLsAHpDF7spiIcSVM97t8GUderLTeKaJCkO1ieCSmdF+u\n"
                + "VuOoT/iISYRkx1ialR2ABJhxiLse+uoDi3oRNzo/OuC9J8rwXrCjNEOP28NH2zur\n"
                + "TK/n4oISZ4KzAoIBAQCny0iqpgd/Pc9Wa1y+1+15lN5s7v2DKDrYRryYVCJ7EVOc\n"
                + "pSh2h3+m9d+vuoszqDCiy6JDb8O4NftLzqxjYShb6cnxGQyd+SoonuZg4LhUKqWn\n"
                + "tmqi+bWsa/az3TBj219SMaRUAjJNRDtoBW1mJ+UAgARUE9J/Uq+m3ErstQE9w4M4\n"
                + "ivgGHbMEFeww+FvzuCI6LKTviwXK4wXLAQAdYae52iAZM2qfyWcXKAUl7qvPcLII\n"
                + "s1QRfdFYJdspovUv6LakoSN+clbFPVYkVhQlzKkssL/9I9IxIW+mt576HnyPM7AC\n"
                + "E6GAsEu89sb1Fxb3eDA54Hon6FmrVfbIpwaPlGJRAoIBAFDnGEwfJtBQhsWSsfjk\n"
                + "EajuhRNoxQLAfL5PsPrM8dDe5BTOhkmstdgxM7zFSLEMi5UTbPk5ubAWTfJSYoPE\n"
                + "P6uhMwbskpCU5R2DAkkhmt/bVJiz89fhTmv0E1aorJCD4iL2iieLnbY3WeLdI2JO\n"
                + "7sa+OgCRKK6nYHl3gXP3OAhZMCa48Il5DUZuNiPpZK/ZuTpaYjgUHjnbxtC3rzPJ\n"
                + "hv992p9Ncl5U0kpXZ38Jr6nsc+ksc0M9s+dEHAtHSuoTgwXLhEoVR7qDQPZIV/12\n"
                + "URKlfTTxPcR81XrLARo8qgvuMO2K51tdcy+3jDrTZI6bCeg51wVVWqfJI4uVHWq4\n"
                + "c40CggEBAOMsl8q5WXtPNxDgiYyU7NFrw7kziptrlzMzbdutEXVQ3YpuSIWvGi6G\n"
                + "BHArQwPDyVoDkmgvZQbf8Q7cdIvngwN2xjGj7fPzLtAcGgAZMFm3fO8BBsci3bKp\n"
                + "+rfZOxsf7g8yLRecq+KCUMpNHTjLD2RxiAZ3qiNifEMgUtK3cSgO64BtfKmJKT5l\n"
                + "dZ7xnYEDi+r5H91IWytVmVN9E8T0KUubaMc7O+X+OXoVdCAa1dohmWtIvozzXwze\n"
                + "S5cA+zjGKMay92rdOw/1HIIUELoZi66DeiowK9PBiyDs41IWCzk1Sh6Ut5c7pn4/\n"
                + "mKWiQvD25GfgiloS+XH8jgDGoHmNAiQ=";

        stream = new ByteArrayInputStream(content.getBytes());
        manager.getPrivateKey(stream, "RSA");
    }

    @Test
    public void testGetterPrivateKeyEntradaOk() throws CertificateException {

        String content = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDTgtWUSmGb0q7B\n"
                + "pX++9DZXQoht6jD9McQiQznCGzm1etMoXIHU/2DtBiNLd8rhSDm1Aq/ZmntvDiJC\n"
                + "eaaV7xDBs3HDMhNZRu+MF29doYPIeUmB+kuWp60/9MoBsv6ppGwUyPVmkj2T4L4Y\n"
                + "gSo3xgBbctMOz/XDswLqX/I/NbEZWYZCBl+59/VnFOr5LofYwp5kHfOnPkp0poCP\n"
                + "Wi/L3ZTpV2rBpZCGohMd0vkG6DlOiwEdYn492hb/jYaK56ATJUyGFrFjAssA1QNM\n"
                + "ubWPR65sO1or9/JKe4P8t2UQjg1ig4JnP23sU7+hTX49v74tZs7jfHcC7Zj7q1D0\n"
                + "E3X//Ggd2y0IZ698dAA+RcEQSyzCoeDhJNzKprBesq5wblLMSzZUPnUxKtgJkQKF\n"
                + "RoRzui8WknqEZOY2PkW52fRqraqZmfagInKcLV+cR6rQg2jMQPIYvHYtTyqXrmrC\n"
                + "xkIPW4bIJYra6Wrr4HqDoHCy7Y+V7/aPtr4pDqA/vdcLHEIs7Md1xLDQp9Bb6zJv\n"
                + "vFWMti8KaNG0zeXQYSmR+iECSOrKRzLYC07PIAF1XqCRqVK3Ex9WLPNblE4qJFtr\n"
                + "IXBVgrPjzJXR7SCgu4dy9VGhiixaaM0qW3Y8duKWTuVM+4eacIMcGCQRAFzpWUQm\n"
                + "aE79G9dAouqv9hHcPLJWZBH4zcZOewIDAQABAoICAFZScE5sKPgKfS4lGETbsI3e\n"
                + "ZoXNbZ74P57oJtt0dxH9Bc7UKly+uVUjCyaSxmc5LewVI6XAqZ3Ce/L7aSSKBCG5\n"
                + "1bUfa8wk6kEXk2j4MSuRbJGykET1O/z9L7CP1+VuaHn3JkhtaNpAf/TKSmum0KCB\n"
                + "9Wd3MktjdM4oyFpJ1HSPF/88ULc6XppqbBe0iNbLXw9nNfjMsGB5T8Cxww4F6e9t\n"
                + "sPFFW/3GidzDLMVH45ONoa/XccRWjMpRfVaVf7wwndGf01egXS+CwC0BIftO+v3L\n"
                + "H1sQf38sd8qdIo8mGopZN9Bhj8BC0dPIJ7yV08z9x3QKaRv10ljsK0bh5mfKIMdI\n"
                + "qxUvEfIogFqpmNZJj2avB4KR7kH69Z5FXeDj9bSqPfbyymXhTviDlXmWYUMOeboI\n"
                + "1WxV5gF8vz5xDQWE5isA3X5WEXxHhtsfu55NG14biO+3CSiC703G0whEVCUJwT/W\n"
                + "tV7us8M2JEJ66bAVYN4OkpDx7sumYsaatGuLnH9NuBfiUf5F1mri8ObOF8h8hhS7\n"
                + "kAmbAwa3nMH1O8Yc7D9uz5yuFJx7Tyh6zhMvCVb8VFUW4TuGkY0G2GTrD+QT6+8N\n"
                + "3rQSHNv9u6BNXb2LfajH0x4c6ASRnTe80NbTWHv7jVMY4qjnauvW8wS5MK5cKkQE\n"
                + "QWltm+EwLDTgKa27hcqRAoIBAQDpOnpeh/Gx3bMeq2SvdnZOQyxvDSnZ6o22UdZ9\n"
                + "8jlwh8X1bXQXaWXnKblAcDXwAyaTjZLzA0kijTUORL0AILo8q3kanB4joIdbFHEm\n"
                + "L6JKv13SyJ8Gs60HA06miE2VBCeOjQGmDt4bNGBdIYeBt6GdtdDqgsyfIjYFV6Fy\n"
                + "ErAgKxf83N/Urp5Ep8tOamEfewgfyfYCwgkAZ/01mqjN+30aeSzEkPdXUSoli6MU\n"
                + "YZwb6QfLH89gxkGvh9/azwfSunvi5ZSwgvGnLJ25gTwwyGhL+tAnollEDRQUPLX2\n"
                + "Ul5wTgGo/vzinVOyZNBtGaj37V1HYThvpMsVI/Gdf1EpxMkZAoIBAQDoKYh0TWwq\n"
                + "I9ChV4pL+koVNc4eD9UVyRF+32rl8tMdlAq2eSQS9H5oPJMiVaf3F1hTYwB6ZFWS\n"
                + "A24x/2Gz5ZWZYGh5DpEEgAe9MYVTdsCX+qtel0m7xSdy4R8Updhr+U3Y9D4fleI0\n"
                + "HPdZSHXTrn9bgJR9CuMZoBUsO2XMOFxcShPFuTF135GDtF2OEAOC4qp5JY7QEosy\n"
                + "qp1LsP7OTkXS0DRWoH4JLsAHpDF7spiIcSVM97t8GUderLTeKaJCkO1ieCSmdF+u\n"
                + "VuOoT/iISYRkx1ialR2ABJhxiLse+uoDi3oRNzo/OuC9J8rwXrCjNEOP28NH2zur\n"
                + "TK/n4oISZ4KzAoIBAQCny0iqpgd/Pc9Wa1y+1+15lN5s7v2DKDrYRryYVCJ7EVOc\n"
                + "pSh2h3+m9d+vuoszqDCiy6JDb8O4NftLzqxjYShb6cnxGQyd+SoonuZg4LhUKqWn\n"
                + "tmqi+bWsa/az3TBj219SMaRUAjJNRDtoBW1mJ+UAgARUE9J/Uq+m3ErstQE9w4M4\n"
                + "ivgGHbMEFeww+FvzuCI6LKTviwXK4wXLAQAdYae52iAZM2qfyWcXKAUl7qvPcLII\n"
                + "s1QRfdFYJdspovUv6LakoSN+clbFPVYkVhQlzKkssL/9I9IxIW+mt576HnyPM7AC\n"
                + "E6GAsEu89sb1Fxb3eDA54Hon6FmrVfbIpwaPlGJRAoIBAFDnGEwfJtBQhsWSsfjk\n"
                + "EajuhRNoxQLAfL5PsPrM8dDe5BTOhkmstdgxM7zFSLEMi5UTbPk5ubAWTfJSYoPE\n"
                + "P6uhMwbskpCU5R2DAkkhmt/bVJiz89fhTmv0E1aorJCD4iL2iieLnbY3WeLdI2JO\n"
                + "7sa+OgCRKK6nYHl3gXP3OAhZMCa48Il5DUZuNiPpZK/ZuTpaYjgUHjnbxtC3rzPJ\n"
                + "hv992p9Ncl5U0kpXZ38Jr6nsc+ksc0M9s+dEHAtHSuoTgwXLhEoVR7qDQPZIV/12\n"
                + "URKlfTTxPcR81XrLARo8qgvuMO2K51tdcy+3jDrTZI6bCeg51wVVWqfJI4uVHWq4\n"
                + "c40CggEBAOMsl8q5WXtPNxDgiYyU7NFrw7kziptrlzMzbdutEXVQ3YpuSIWvGi6G\n"
                + "BHArQwPDyVoDkmgvZQbf8Q7cdIvngwN2xjGj7fPzLtAcGgAZMFm3fO8BBsci3bKp\n"
                + "+rfZOxsf7g8yLRecq+KCUMpNHTjLD2RxiAZ3qiNifEMgUtK3cSgO64BtfKmJKT5l\n"
                + "dZ7xnYEDi+r5H91IWytVmVN9E8T0KUubaMc7O+X+OXoVdCAa1dohmWtIvozzXwze\n"
                + "S5cA+zjGKMay92rdOw/1HIIUELoZi66DeiowK9PBiyDs41IWCzk1Sh6Ut5c7pn4/\n"
                + "mKWiQvD25GfgiloS+XH8jgDGoHmNAiQ=";

        stream = new ByteArrayInputStream(content.getBytes());
        PrivateKey result = manager.getPrivateKey(stream, "RSA");

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testGetterPrivateKeyEntradaOk2() throws CertificateException {

        String content = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAr73mlq+Wv9ABdqNF\n"
                + "guGFN/QxPLzGU3V1mhUV9EhRrQof598deEroqkmmXt94WmolKUZb5r/PvuGWKZiQ\n"
                + "0xTP5wIDAQABAkBWQrf0Lqun6slNGkb8PwXMuSeR0HbocDcRMlhcV0L/06/zlm+s\n"
                + "aN14QlhtN+vMK930clTQUY1FKEMFBb+FmYxBAiEA3hhrv/Hqar+ezPdCfEYEUGcH\n"
                + "oNPObn0LXKoKnM+L78UCIQDKkfZdDn1x3/kWyDD/3fdapTYP61sVkaEwiwIbZXGv\n"
                + "uwIgNB+9IhZPsu/4ABjDxNDV8FzN4IP1Pd8hDIVn6jeXmxUCIE+Ac7lX64Hazk7T\n"
                + "qO9ytRadSpd63lebvTBpDh2kdbbrAiAuP3tZwjnDRaJEMkjkZSoDuK+czrK9yFx/\n"
                + "NmP6rluKnQ==";

        stream = new ByteArrayInputStream(content.getBytes());
        PrivateKey result = manager.getPrivateKey(stream, "RSA");

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testGetterPrivateKeyEntradaOk3() throws CertificateException {

        String content = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAJVCOnfaBkBNxb6iQ\n"
                + "9StoDaXm/NX29Z6cANilamcQgPDHZ1hnY1rdL8sdKxUhdC+3vQXc5tkwhH+P7BX0\n"
                + "ul5hCmihgYkDgYYABACIOGZoih8y38SSgBuAfJ8cIzwFQHN2tWP6bfCsvc1xL4nu\n"
                + "uOalU2e+mq4mkB9A4Cm/3vLzSoqDWhOn5OBfeFCd1gB/Qb7aQUFCsxq8oCZXrjPu\n"
                + "vbH2jdz2WoKr02uGJP1gnpZzZpj20W1ZWpmZKtqN8DWgInoorKrubxKJTAsJzd50\n"
                + "6g==";

        stream = new ByteArrayInputStream(content.getBytes());
        PrivateKey result = manager.getPrivateKey(stream, "EC");

        Assert.assertNotNull(result);
        Assert.assertEquals("EC", result.getAlgorithm());
    }

    @Test(expected = CertificateException.class)
    public void testGetterPrivateKeyEntradaError2() throws CertificateException {

        String content = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAJVCOnfaBkBNxb6iQ\n"
                + "9StoDaXm/NX29Z6cANilamcQgPDHZ1hnY1rdL8sdKxUhdC+3vQXc5tkwhH+P7BX0\n"
                + "ul5hCmihgYkDgYYABACIOGZoih8y38SSgBuAfJ8cIzwFQHN2tWP6bfCsvc1xL4nu\n"
                + "................................................................\n"
                + "vbH2jdz2WoKr02uGJP1gnpZzZpj20W1ZWpmZKtqN8DWgInoorKrubxKJTAsJzd50\n"
                + "6g==";

        stream = new ByteArrayInputStream(content.getBytes());
        manager.getPrivateKey(stream, "EC");
    }

    @Test
    public void testCertificateValidator_RSA_4096() throws CertificateException {

        String content = "-----BEGIN CERTIFICATE-----\n"
                + "\n"
                + "MIIEwjCCAqqgAwIBAgIGAW5lL31mMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMTB2V4YW1wbGUw\n"
                + "HhcNMTkxMTEyMTQzNDAxWhcNMTkxMDI4MjI1MjEyWjAWMRQwEgYKCZImiZPyLGQBGRYEbmFtZTCC\n"
                + "AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJSHfEFXEnOx60AeDe6budYjSRlPSdVA/RHs\n"
                + "0OoVCRdLwX+MvVVCkwu7zPbk+vtfrM2BU5qBehVq6naJallAV6DDrvlFYxTeKksougmKvMdpG/XZ\n"
                + "Bo2CeEgR/c0xIGzNvkPJ4TeVCpFVm66QKoJgcJAEXOBflBxp+I5fZmT4ljHyRb+1vhy9HSs7Kbeb\n"
                + "1pSavy4drrA554m/+rMwnVO6srtPIdh9fQnBIvmpTsu8NK4PdFRXcDYHTAbmCh6GtqdkZjcsOgOT\n"
                + "wZWaEc+Zm31U9MHZlMoNEfSKBJL6ckIsCCXD1QpxFeAiuedn7Qmh8vsGnDex64dSYNcV4Bc75Mtn\n"
                + "nnE4AYfULF0dNzjJVSZMmyxQrv2WA86sNWrQR+oeeNgCPwMWxnW6I0CjPPI/tiwcxd/Y5Nk3Y/Le\n"
                + "StbMhz705JR6rdBPVwmX/oYGbwP5TmFBgNC0hn7T0zO1UmV9lrh5X94ySuCrK+wV86Y5u2i6R7QO\n"
                + "gTYJCAW019V4ePNdduggzvSQXQyWTpE96KvUXqop4e5W7YIc+LWGVQeW2gPLcHprnlRqwStwsP6Q\n"
                + "xZ0ebmycbiuNVlqZsNpqSST+ikgMYCbXTvLVrduJAEBW8Lj+7AgB6cBqP7P7LavfJVzE2hnjRYaV\n"
                + "YlxYfvMjJ2mhargoew8XthCMs5ubTjwtCjUtmT8VAgMBAAGjGjAYMBYGA1UdJQEB/wQMMAoGCCsG\n"
                + "AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQCAVHvikGaVxqho3ed6xgXr/TXlWy4OCH/b4rbqxRc6\n"
                + "il9AZRvjFCjy3CuxQ0ZKEOmenQLHo/H2R+2KoU9rvBra+BdyUefpsYIzsq05mFmKDXUZkWurMSAE\n"
                + "jzxVqftE/MC3ysI4dzy1Bwwb8/1dZRahQVT9+4iBuKfn0/F1B7JMGbFINMDM21PgAVhCfSlwGbH6\n"
                + "kHWFdU68HLSy6ll14saALnqTP+/+jgUKg6EP3bG3kgrTz+Ui99qRxV5J6wlsD5SPnFmj6ufIE66W\n"
                + "GbGWYg0OqLNqw7vRKdx+P4Nqm4xVFmBU6/MNDnm7uJUl7uiOG6NcbQd4XaLK2WKoCqU/2dq8tR53\n"
                + "DNc0G515INt6qPbLVdCrTl0uIDFA48CbFPME+bEllqvrR5UYEst+467BEteqQf/w2qO5yqHhlX0S\n"
                + "oKhtWWvVKREOhNEyAIQ2sXf5GGmNKR/VzCWvwkt5v6tFKaJXRfWwX3ax6FlNQ7ZfVcIfKIoHhzIx\n"
                + "wC6rcu2g+KUqP1OXQZu+0T9+CvWOGKqk7hwY9rokernNDl5szhc1tbGn7qfZIaS7v4ZWt5BG49uI\n"
                + "VJ89t6GiPKqG22IMMjSRBSUq8+GkpniQVC4SRSoOk9AwhbhIS7bbYPVjoB/gs9KGIS9TXRV/Qefx\n"
                + "AMTN5atC6SyMkAr/HCcP5Icip6sWl1WV+g==\n"
                + "\n"
                + "-----END CERTIFICATE-----";

        stream = new ByteArrayInputStream(content.getBytes());
        PublicKey result = manager.getPublicKey(stream);

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testPrivateKeyValidator_RSA_4096() throws CertificateException {

        String content = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCUh3xBVxJzsetAHg3um7nWI0kZ\n"
                + "T0nVQP0R7NDqFQkXS8F/jL1VQpMLu8z25Pr7X6zNgVOagXoVaup2iWpZQFegw675RWMU3ipLKLoJ\n"
                + "irzHaRv12QaNgnhIEf3NMSBszb5DyeE3lQqRVZuukCqCYHCQBFzgX5QcafiOX2Zk+JYx8kW/tb4c\n"
                + "vR0rOym3m9aUmr8uHa6wOeeJv/qzMJ1TurK7TyHYfX0JwSL5qU7LvDSuD3RUV3A2B0wG5goehran\n"
                + "ZGY3LDoDk8GVmhHPmZt9VPTB2ZTKDRH0igSS+nJCLAglw9UKcRXgIrnnZ+0JofL7Bpw3seuHUmDX\n"
                + "FeAXO+TLZ55xOAGH1CxdHTc4yVUmTJssUK79lgPOrDVq0EfqHnjYAj8DFsZ1uiNAozzyP7YsHMXf\n"
                + "2OTZN2Py3krWzIc+9OSUeq3QT1cJl/6GBm8D+U5hQYDQtIZ+09MztVJlfZa4eV/eMkrgqyvsFfOm\n"
                + "Obtouke0DoE2CQgFtNfVeHjzXXboIM70kF0Mlk6RPeir1F6qKeHuVu2CHPi1hlUHltoDy3B6a55U\n"
                + "asErcLD+kMWdHm5snG4rjVZambDaakkk/opIDGAm107y1a3biQBAVvC4/uwIAenAaj+z+y2r3yVc\n"
                + "xNoZ40WGlWJcWH7zIydpoWq4KHsPF7YQjLObm048LQo1LZk/FQIDAQABAoICAAUjRqYP+ABuiB+4\n"
                + "qmy1kFEa+V1Zw8kPrXFgSr2+KolWwoPB/46idemy/l0QAKqPXa/iKF0w22NARooBKN+bfSx/eF8B\n"
                + "CnNfWAEvkHfiB7OyLBhuAG8Gs1hy3t+pMmDxIQLBSfwdOLdcSb1ZGU9XPK2OqRPN2pa9B68NF8Ko\n"
                + "YrGpmsYN6FygIhErw76pMlwDmldjCXbpGdxG+soWBWsvCx21mAsgFCIxPx95vtMHWJ8ow7JjL+t+\n"
                + "hx+592Gk8U6LB4ojCoKzKsAdCz6uJpXISYsnFqGCoDtgRtY6uZcWZNXBl238CXCuYtXhX2603m3W\n"
                + "hbLbgbU1oUnvZMgI91od5Hoil6zx3kW3Je+sAhZqINHhmDimlML5iGGec4db//9WQVISpt/819JH\n"
                + "FlJDZmxB3gN5p7Tr5l6dvwnG0AaXLKlDPbJu4bDgS1ET4k5Xflk414LJ+go4ZGns9W7mVOihmENZ\n"
                + "0VhRJ2swpcJM1d44eC7JR2RzALRoN2pCBCvnqc3Xl1iz3eotWub61uuoBDHtnqBb5qkBrzaQ7MK2\n"
                + "bT+uvhX7iiwqw3WTsiAguNsDx15F7T6LDrmecLpgdvyXOAQVorNtBUWQTncO+mazVi+VG+WxWI1I\n"
                + "kQqfTWvmIpzm4/edsi86BioRA1xtfH6cv8skSEeZIw8AFdxCkUkbgK7YhpDlAoIBAQDTopRz686M\n"
                + "KTt8MqXuGhcUTFAvgZZVCzhJJyEAS6mVUUcvOc/2CwdALfjarFJbS+APZZhYtge8ipvxHWQq93n4\n"
                + "AQd2IdYHssnynpn010JtIQWr4Lldtue98bkr/1F6v/tlKSrOO/8KxVlS4gjNNI2uyc7qa7MSXmrw\n"
                + "USgT8fjkpIksFez5J5F5DzsklJbxchLWMh8oN9439nv0egD+1FmeOn7RHnp6DovNBIK9CP4HNsVi\n"
                + "91GRvU4UgpCmbZRBJR/rhYirITzq2fVboYjGXSmVEBIP6FsS9pn821lE8Fek+x3qLJ4ZR+3MSf3Y\n"
                + "x2Y3M/+5KFyisq4HoEb8KYEu11A7AoIBAQCzqlLZSGVNOe/7hHjkSxqcBV+7CuiyB2ZEJamqRo0k\n"
                + "BJ7iz/3EHb5sI0LTvXB6MMkOXEtqj17dzzCZCUI0f6FaenT+O6pcquNaPFgyr7pOIxTU1aENBOKt\n"
                + "tdWQD3IBHu6mNQFabR7V/8gJC9h9zG4kTESiCZZl93/TbXo52wn0GTjHBGFONYdOvdShzbHmgQY9\n"
                + "4ONP+LXdaGkrzwDhagVKfi3NK9suAE78GwVOCvk4j1BzLWKPwqwoc6/C+7GwCjyXd12Q9/g61kQC\n"
                + "jKDi6DbuO/egqBEpQTXYEW8sQDOoWW/CbaFuXn6jNfFYkir5lh7n6Jdw2e4X2kLLRPDWgojvAoIB\n"
                + "AQCG+dwAitZy4iFENvFJCG7LzVge1GFS4BMH5OLRU3BXAT2LSy3tWF9JeYiLvvfPrna6myss+Pu6\n"
                + "LhUDFKG8HZY2rEFcAHyG8GqISMscMuX0v+jkFDFlKbBnnnFhNDd9OFBX1oesfOtOrUso52yBpBDw\n"
                + "91j2fbX58yn1F22eOudou9+YtGstBSVstmAcFoCmgQCuh80DU45w1s17wQw9eqWlmt0i9nNawUg8\n"
                + "e7H+amvJog8F7YKilr/jqNokqyKw4cKX7dSagFpf1p77z+xxxx0sKtG6P5FGaO0RLbyjkT30xQvx\n"
                + "PH+g1BVAA7jYt2PjtVBVgP6D7b28s2ZSkQ4JF93dAoIBABhDsYq810mVwI50dqtGZWKa6zHkqEaa\n"
                + "7znW6FIh0yABK8AwHPKmnbgXDwhvtkgaXJz+5ASRNlu4hrS0ZmeWsSD6FuDbCAgZ4Diom7TEvOGe\n"
                + "pUqVS3nppf+V5jDdlSUHm22BDRy8TgTS1Z47JlLfECUA0+gaaWB+C5pvV6mGppJ78YoXUljwq8R7\n"
                + "qMLtd9BMrp4eyDRdv5oWZtXO0CyhV/OWlPL3sFNHIWO09oNywfPcjx3vDDekMAIKlbs8qOPAjixa\n"
                + "p51TkAfKNkct3PCoMfr8yFW/PQoYT4BN4njUduWOpqRYkAvK4UmDmIPAweMRXj0t0X4hQKGiDZFM\n"
                + "T0Z5PKsCggEBAMNDxowd2Et+n0lEDkLKl2W2mAYkTwwQf9WuKLFqlPZKgvlQHeaXll9VrQq55WF5\n"
                + "nxiHZHIx0gE5PCN1V8iNLJvJbZOz4g0mvOpJy5u0BQznkDT7XGtj+CZn2w/TPBgOLQj3C5HbjkOb\n"
                + "7pY/+Xs2SPlGtvE7t3fSXLPI5CMFS4YtAsJSSYQBpqRGvFoHt15ILzkkqw1HqEoZ6p0zvg51xCUK\n"
                + "QbysYAa1cRCOczo/l6fBPauRSm45Es2FU/q9O4cEwy3arW3FWh8Ecu4F93Ga4vb3aRgnw7OWGdV8\n"
                + "STUkcRHyjesMULYVcoU8O/bFi4dFFdIKsDnU4nkr6aXhRJjF1vg=";

        stream = new ByteArrayInputStream(content.getBytes());
        PrivateKey result = manager.getPrivateKey(stream, "RSA");

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

}
