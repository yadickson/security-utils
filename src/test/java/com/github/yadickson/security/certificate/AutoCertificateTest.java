/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.certificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.it.Verifier;
import org.apache.maven.it.util.ResourceExtractor;
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
public class AutoCertificateTest {

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

    @Test
    public void testGetterCertificateKeyRSAOk() throws Exception {

        Verifier verifier;

        File testDir = ResourceExtractor.simpleExtractResources(getClass(), "/files");

        verifier = new Verifier(testDir.getAbsolutePath());

        List<String> cliOptions = new ArrayList<>();

        cliOptions.add("-f");
        cliOptions.add("testRSA.xml");

        verifier.setCliOptions(cliOptions);

        List<String> goals = new ArrayList<>();

        goals.add("clean");
        goals.add("package");

        verifier.executeGoals(goals);
        verifier.verifyErrorFreeLog();
        verifier.resetStreams();

        File file = new File("./target/testRSA/cert.pem");

        Assert.assertTrue(file.exists());

        stream = new FileInputStream(file);
        PublicKey result = manager.getPublicKey(stream);

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testGetterCertificateKeyECDSAOk() throws Exception {

        Verifier verifier;

        File testDir = ResourceExtractor.simpleExtractResources(getClass(), "/files");

        verifier = new Verifier(testDir.getAbsolutePath());

        List<String> cliOptions = new ArrayList<>();

        cliOptions.add("-f");
        cliOptions.add("testEC.xml");

        verifier.setCliOptions(cliOptions);

        List<String> goals = new ArrayList<>();

        goals.add("clean");
        goals.add("package");

        verifier.executeGoals(goals);
        verifier.verifyErrorFreeLog();
        verifier.resetStreams();

        File file = new File("./target/testEC/cert.pem");

        Assert.assertTrue(file.exists());

        stream = new FileInputStream(file);
        PublicKey result = manager.getPublicKey(stream);

        Assert.assertNotNull(result);
        Assert.assertEquals("EC", result.getAlgorithm());
    }

    @Test
    public void testGetterPrivateKeyRSAOk() throws Exception {

        Verifier verifier;

        File testDir = ResourceExtractor.simpleExtractResources(getClass(), "/files");

        verifier = new Verifier(testDir.getAbsolutePath());

        List<String> cliOptions = new ArrayList<>();

        cliOptions.add("-f");
        cliOptions.add("testRSA.xml");

        verifier.setCliOptions(cliOptions);

        List<String> goals = new ArrayList<>();

        goals.add("clean");
        goals.add("package");

        verifier.executeGoals(goals);
        verifier.verifyErrorFreeLog();
        verifier.resetStreams();

        File file = new File("./target/testRSA/key.pem");

        Assert.assertTrue(file.exists());

        stream = new FileInputStream(file);
        PrivateKey result = manager.getPrivateKey(stream, "RSA");

        Assert.assertNotNull(result);
        Assert.assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    public void testGetterPrivateKeyECDSAOk() throws Exception {

        Verifier verifier;

        File testDir = ResourceExtractor.simpleExtractResources(getClass(), "/files");

        verifier = new Verifier(testDir.getAbsolutePath());

        List<String> cliOptions = new ArrayList<>();

        cliOptions.add("-f");
        cliOptions.add("testEC.xml");

        verifier.setCliOptions(cliOptions);

        List<String> goals = new ArrayList<>();

        goals.add("clean");
        goals.add("package");

        verifier.executeGoals(goals);
        verifier.verifyErrorFreeLog();
        verifier.resetStreams();

        File file = new File("./target/testEC/key.pem");

        Assert.assertTrue(file.exists());

        stream = new FileInputStream(file);
        PrivateKey result = manager.getPrivateKey(stream, "EC");

        Assert.assertNotNull(result);
        Assert.assertEquals("EC", result.getAlgorithm());
    }

}
