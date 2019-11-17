/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.util;

import com.github.yadickson.security.exception.CertificateException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.codec.binary.Base64;
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
public class KeyManagerTest {

    private InputStream stream;

    @InjectMocks
    KeyManagerImpl manager;

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
    public void testObtenerBase64EntradaNula() throws CertificateException {
        manager.getBase64(stream);
    }

    @Test
    public void testObtenerBase64Ok() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("rsa/key.pem");
        String result = manager.getBase64(stream);
        Assert.assertNotNull(result);
        Assert.assertTrue(Base64.isBase64(result));
    }

    @Test
    public void testObtenerBase64Ok2() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("rsa/servertest.key");
        String result = manager.getBase64(stream);
        Assert.assertNotNull(result);
        Assert.assertTrue(Base64.isBase64(result));
    }

    @Test
    public void testObtenerBase64Ok3() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("ec/key.pem");
        String result = manager.getBase64(stream);
        Assert.assertNotNull(result);
        Assert.assertTrue(Base64.isBase64(result));
    }

    @Test(expected = CertificateException.class)
    public void testObtenerClavePublicaEntradaNull() throws CertificateException {
        manager.getPublicKey(stream);
    }

    @Test(expected = CertificateException.class)
    public void testObtenerClavePublicaError() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("rsa/key.pem");
        manager.getPublicKey(stream);
    }

    @Test(expected = CertificateException.class)
    public void testObtenerClavePublicaError2() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("ec/key.pem");
        manager.getPublicKey(stream);
    }

    @Test
    public void testObtenerClavePublicaOk() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("rsa/cert.pem");
        PublicKey key = manager.getPublicKey(stream);
        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    public void testObtenerClavePublicaOk2() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("rsa/servertest.crt");
        PublicKey key = manager.getPublicKey(stream);
        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    public void testObtenerClavePublicaOk3() throws CertificateException {
        stream = KeyManagerTest.class.getClassLoader().getResourceAsStream("ec/cert.pem");
        PublicKey key = manager.getPublicKey(stream);
        Assert.assertNotNull(key);
        Assert.assertEquals("EC", key.getAlgorithm());
    }

    @Test(expected = CertificateException.class)
    public void testObtenerClavePrivadaEntradaNula() throws CertificateException {
        manager.getPrivateKey(null, "RSA");
    }

    @Test
    public void testObtenerClavePrivadaOk() throws CertificateException {

        String b64 = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAr73mlq+Wv9ABdqNF\n"
                + "guGFN/QxPLzGU3V1mhUV9EhRrQof598deEroqkmmXt94WmolKUZb5r/PvuGWKZiQ\n"
                + "0xTP5wIDAQABAkBWQrf0Lqun6slNGkb8PwXMuSeR0HbocDcRMlhcV0L/06/zlm+s\n"
                + "aN14QlhtN+vMK930clTQUY1FKEMFBb+FmYxBAiEA3hhrv/Hqar+ezPdCfEYEUGcH\n"
                + "oNPObn0LXKoKnM+L78UCIQDKkfZdDn1x3/kWyDD/3fdapTYP61sVkaEwiwIbZXGv\n"
                + "uwIgNB+9IhZPsu/4ABjDxNDV8FzN4IP1Pd8hDIVn6jeXmxUCIE+Ac7lX64Hazk7T\n"
                + "qO9ytRadSpd63lebvTBpDh2kdbbrAiAuP3tZwjnDRaJEMkjkZSoDuK+czrK9yFx/\n"
                + "NmP6rluKnQ==\n";

        PrivateKey result = manager.getPrivateKey(b64, "RSA");
        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testObtenerClavePrivadaOk2() throws CertificateException {

        String b64 = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAr73mlq+Wv9ABdqNF\n"
                + "guGFN/QxPLzGU3V1mhUV9EhRrQof598deEroqkmmXt94WmolKUZb5r/PvuGWKZiQ\n"
                + "0xTP5wIDAQABAkBWQrf0Lqun6slNGkb8PwXMuSeR0HbocDcRMlhcV0L/06/zlm+s\n"
                + "aN14QlhtN+vMK930clTQUY1FKEMFBb+FmYxBAiEA3hhrv/Hqar+ezPdCfEYEUGcH\n"
                + "oNPObn0LXKoKnM+L78UCIQDKkfZdDn1x3/kWyDD/3fdapTYP61sVkaEwiwIbZXGv\n"
                + "uwIgNB+9IhZPsu/4ABjDxNDV8FzN4IP1Pd8hDIVn6jeXmxUCIE+Ac7lX64Hazk7T\n"
                + "qO9ytRadSpd63lebvTBpDh2kdbbrAiAuP3tZwjnDRaJEMkjkZSoDuK+czrK9yFx/\n"
                + "NmP6rluKnQ==\n";

        PrivateKey result = manager.getPrivateKey(b64, "RSA");
        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testObtenerClavePrivadaOk3() throws CertificateException {

        String b64 = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDTgtWUSmGb0q7B\n"
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
                + "mKWiQvD25GfgiloS+XH8jgDGoHmNAiQ=\n";

        PrivateKey result = manager.getPrivateKey(b64, "RSA");
        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testObtenerClavePrivadaOk4() throws CertificateException {

        String b64 = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDTgtWUSmGb0q7B\n\r"
                + "pX++9DZXQoht6jD9McQiQznCGzm1etMoXIHU/2DtBiNLd8rhSDm1Aq/ZmntvDiJC\n\r"
                + "eaaV7xDBs3HDMhNZRu+MF29doYPIeUmB+kuWp60/9MoBsv6ppGwUyPVmkj2T4L4Y\n\r"
                + "gSo3xgBbctMOz/XDswLqX/I/NbEZWYZCBl+59/VnFOr5LofYwp5kHfOnPkp0poCP\n\r"
                + "Wi/L3ZTpV2rBpZCGohMd0vkG6DlOiwEdYn492hb/jYaK56ATJUyGFrFjAssA1QNM\n\r"
                + "ubWPR65sO1or9/JKe4P8t2UQjg1ig4JnP23sU7+hTX49v74tZs7jfHcC7Zj7q1D0\n\r"
                + "E3X//Ggd2y0IZ698dAA+RcEQSyzCoeDhJNzKprBesq5wblLMSzZUPnUxKtgJkQKF\n\r"
                + "RoRzui8WknqEZOY2PkW52fRqraqZmfagInKcLV+cR6rQg2jMQPIYvHYtTyqXrmrC\n\r"
                + "xkIPW4bIJYra6Wrr4HqDoHCy7Y+V7/aPtr4pDqA/vdcLHEIs7Md1xLDQp9Bb6zJv\n\r"
                + "vFWMti8KaNG0zeXQYSmR+iECSOrKRzLYC07PIAF1XqCRqVK3Ex9WLPNblE4qJFtr\n\r"
                + "IXBVgrPjzJXR7SCgu4dy9VGhiixaaM0qW3Y8duKWTuVM+4eacIMcGCQRAFzpWUQm\n\r"
                + "aE79G9dAouqv9hHcPLJWZBH4zcZOewIDAQABAoICAFZScE5sKPgKfS4lGETbsI3e\n\r"
                + "ZoXNbZ74P57oJtt0dxH9Bc7UKly+uVUjCyaSxmc5LewVI6XAqZ3Ce/L7aSSKBCG5\n\r"
                + "1bUfa8wk6kEXk2j4MSuRbJGykET1O/z9L7CP1+VuaHn3JkhtaNpAf/TKSmum0KCB\n\r"
                + "9Wd3MktjdM4oyFpJ1HSPF/88ULc6XppqbBe0iNbLXw9nNfjMsGB5T8Cxww4F6e9t\n\r"
                + "sPFFW/3GidzDLMVH45ONoa/XccRWjMpRfVaVf7wwndGf01egXS+CwC0BIftO+v3L\n\r"
                + "H1sQf38sd8qdIo8mGopZN9Bhj8BC0dPIJ7yV08z9x3QKaRv10ljsK0bh5mfKIMdI\n\r"
                + "qxUvEfIogFqpmNZJj2avB4KR7kH69Z5FXeDj9bSqPfbyymXhTviDlXmWYUMOeboI\n\r"
                + "1WxV5gF8vz5xDQWE5isA3X5WEXxHhtsfu55NG14biO+3CSiC703G0whEVCUJwT/W\n\r"
                + "tV7us8M2JEJ66bAVYN4OkpDx7sumYsaatGuLnH9NuBfiUf5F1mri8ObOF8h8hhS7\n\r"
                + "kAmbAwa3nMH1O8Yc7D9uz5yuFJx7Tyh6zhMvCVb8VFUW4TuGkY0G2GTrD+QT6+8N\n\r"
                + "3rQSHNv9u6BNXb2LfajH0x4c6ASRnTe80NbTWHv7jVMY4qjnauvW8wS5MK5cKkQE\n\r"
                + "QWltm+EwLDTgKa27hcqRAoIBAQDpOnpeh/Gx3bMeq2SvdnZOQyxvDSnZ6o22UdZ9\n\r"
                + "8jlwh8X1bXQXaWXnKblAcDXwAyaTjZLzA0kijTUORL0AILo8q3kanB4joIdbFHEm\n\r"
                + "L6JKv13SyJ8Gs60HA06miE2VBCeOjQGmDt4bNGBdIYeBt6GdtdDqgsyfIjYFV6Fy\n\r"
                + "ErAgKxf83N/Urp5Ep8tOamEfewgfyfYCwgkAZ/01mqjN+30aeSzEkPdXUSoli6MU\n\r"
                + "YZwb6QfLH89gxkGvh9/azwfSunvi5ZSwgvGnLJ25gTwwyGhL+tAnollEDRQUPLX2\n\r"
                + "Ul5wTgGo/vzinVOyZNBtGaj37V1HYThvpMsVI/Gdf1EpxMkZAoIBAQDoKYh0TWwq\n\r"
                + "I9ChV4pL+koVNc4eD9UVyRF+32rl8tMdlAq2eSQS9H5oPJMiVaf3F1hTYwB6ZFWS\n\r"
                + "A24x/2Gz5ZWZYGh5DpEEgAe9MYVTdsCX+qtel0m7xSdy4R8Updhr+U3Y9D4fleI0\n\r"
                + "HPdZSHXTrn9bgJR9CuMZoBUsO2XMOFxcShPFuTF135GDtF2OEAOC4qp5JY7QEosy\n\r"
                + "qp1LsP7OTkXS0DRWoH4JLsAHpDF7spiIcSVM97t8GUderLTeKaJCkO1ieCSmdF+u\n\r"
                + "VuOoT/iISYRkx1ialR2ABJhxiLse+uoDi3oRNzo/OuC9J8rwXrCjNEOP28NH2zur\n\r"
                + "TK/n4oISZ4KzAoIBAQCny0iqpgd/Pc9Wa1y+1+15lN5s7v2DKDrYRryYVCJ7EVOc\n\r"
                + "pSh2h3+m9d+vuoszqDCiy6JDb8O4NftLzqxjYShb6cnxGQyd+SoonuZg4LhUKqWn\n\r"
                + "tmqi+bWsa/az3TBj219SMaRUAjJNRDtoBW1mJ+UAgARUE9J/Uq+m3ErstQE9w4M4\n\r"
                + "ivgGHbMEFeww+FvzuCI6LKTviwXK4wXLAQAdYae52iAZM2qfyWcXKAUl7qvPcLII\n\r"
                + "s1QRfdFYJdspovUv6LakoSN+clbFPVYkVhQlzKkssL/9I9IxIW+mt576HnyPM7AC\n\r"
                + "E6GAsEu89sb1Fxb3eDA54Hon6FmrVfbIpwaPlGJRAoIBAFDnGEwfJtBQhsWSsfjk\n\r"
                + "EajuhRNoxQLAfL5PsPrM8dDe5BTOhkmstdgxM7zFSLEMi5UTbPk5ubAWTfJSYoPE\n\r"
                + "P6uhMwbskpCU5R2DAkkhmt/bVJiz89fhTmv0E1aorJCD4iL2iieLnbY3WeLdI2JO\n\r"
                + "7sa+OgCRKK6nYHl3gXP3OAhZMCa48Il5DUZuNiPpZK/ZuTpaYjgUHjnbxtC3rzPJ\n\r"
                + "hv992p9Ncl5U0kpXZ38Jr6nsc+ksc0M9s+dEHAtHSuoTgwXLhEoVR7qDQPZIV/12\n\r"
                + "URKlfTTxPcR81XrLARo8qgvuMO2K51tdcy+3jDrTZI6bCeg51wVVWqfJI4uVHWq4\n\r"
                + "c40CggEBAOMsl8q5WXtPNxDgiYyU7NFrw7kziptrlzMzbdutEXVQ3YpuSIWvGi6G\n\r"
                + "BHArQwPDyVoDkmgvZQbf8Q7cdIvngwN2xjGj7fPzLtAcGgAZMFm3fO8BBsci3bKp\n\r"
                + "+rfZOxsf7g8yLRecq+KCUMpNHTjLD2RxiAZ3qiNifEMgUtK3cSgO64BtfKmJKT5l\n\r"
                + "dZ7xnYEDi+r5H91IWytVmVN9E8T0KUubaMc7O+X+OXoVdCAa1dohmWtIvozzXwze\n\r"
                + "S5cA+zjGKMay92rdOw/1HIIUELoZi66DeiowK9PBiyDs41IWCzk1Sh6Ut5c7pn4/\n\r"
                + "mKWiQvD25GfgiloS+XH8jgDGoHmNAiQ=\n\r";

        PrivateKey result = manager.getPrivateKey(b64, "RSA");
        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testObtenerClavePrivadaOk5() throws CertificateException {

        String b64 = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBIZRo0qHW56QeAoZT\n"
                + "16ffWJ1Vpqvk3Cm8TG9I4hke9Jo54MS36fA7+tDUQfoYalUS+rVUrzAbi+HrzNBD\n"
                + "d1lVnsuhgYkDgYYABAB3rkjegj5gLTuk5OCOQt+bM1P19xMD+TA0isl83EkrQRxZ\n"
                + "cZjHU5pCH0Ksx0616AVuyAS8pT2APqiLB9VE+kGMmACPrZR/zIYfTBe898CZddI6\n"
                + "TzcCzBWr2+lQl5Jh3DGZ98BRe1OiwnjgswKMgF1+gUsm1MIb0d0WpnDFs7ZzCvdw\n"
                + "bA==";

        PrivateKey result = manager.getPrivateKey(b64, "EC");
        Assert.assertNotNull(result);
        Assert.assertEquals("EC", result.getAlgorithm());
    }

}
