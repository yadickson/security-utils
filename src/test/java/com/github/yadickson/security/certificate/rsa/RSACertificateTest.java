/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.certificate.rsa;

import com.github.yadickson.security.util.*;
import com.github.yadickson.security.exception.CertificateException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

/**
 *
 * @author Yadickson Soto
 */
@RunWith(MockitoJUnitRunner.class)
public class RSACertificateTest {

    private InputStream stream;

    @InjectMocks
    RSACertificateImpl manager;

    @Mock
    KeyManager keyger;

    @Mock
    PublicKey pubk;

    @Mock
    PrivateKey privk;

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

    @Test
    public void testObtenerClavePublicaOk() throws CertificateException {
        stream = RSACertificateTest.class.getClassLoader().getResourceAsStream("ec/cert.pem");
        Mockito.when(keyger.getPublicKey(Mockito.same(stream))).thenReturn(pubk);
        PublicKey result = manager.getPublicKey(stream);
        Assert.assertNotNull(result);
        Assert.assertSame(result, pubk);
        Mockito.verify(keyger, Mockito.times(1)).getPublicKey(Mockito.same(stream));
    }

    @Test
    public void testObtenerClavePrivadaEntradaOk() throws CertificateException {
        stream = RSACertificateTest.class.getClassLoader().getResourceAsStream("rsa/key.pem");
        Mockito.when(keyger.getBase64(Mockito.same(stream))).thenReturn("base64");
        Mockito.when(keyger.getPrivateKey(Mockito.eq("base64"), Mockito.eq("RSA"))).thenReturn(privk);

        PrivateKey result = manager.getPrivateKey(stream);

        Assert.assertSame(result, privk);
        Mockito.verify(keyger, Mockito.times(1)).getBase64(Mockito.same(stream));
        Mockito.verify(keyger, Mockito.times(1)).getPrivateKey(Mockito.eq("base64"), Mockito.eq("RSA"));
    }

    @Test
    public void testObtenerClavePrivadaEntradaOk2() throws CertificateException {
        stream = RSACertificateTest.class.getClassLoader().getResourceAsStream("rsa/servertest.key");
        Mockito.when(keyger.getBase64(Mockito.same(stream))).thenReturn("base64");
        Mockito.when(keyger.getPrivateKey(Mockito.eq("base64"), Mockito.eq("RSA"))).thenReturn(privk);

        PrivateKey result = manager.getPrivateKey(stream);

        Assert.assertSame(result, privk);
        Mockito.verify(keyger, Mockito.times(1)).getBase64(Mockito.same(stream));
        Mockito.verify(keyger, Mockito.times(1)).getPrivateKey(Mockito.eq("base64"), Mockito.eq("RSA"));
    }
}
