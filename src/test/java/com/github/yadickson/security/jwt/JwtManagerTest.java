/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.security.jwt;

import com.github.yadickson.security.certificate.CertificateManagerImpl;
import com.github.yadickson.security.exception.CertificateException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

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
public class JwtManagerTest {

    @InjectMocks
    private JwtManagerImpl manager;

    @InjectMocks
    private CertificateManagerImpl certificate;

    private InputStream streamPrivateKey;

    private InputStream streamPublicKey;

    @Before
    public void before() {
        streamPrivateKey = null;
        streamPublicKey = null;
    }

    @After
    public void after() throws Exception {
        if (streamPrivateKey != null) {
            streamPrivateKey.close();
        }
        if (streamPublicKey != null) {
            streamPublicKey.close();
        }
    }

    @Test
    public void testCreateTokenOk() throws CertificateException {

        String content = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAdQ9nj+bY5G5XLDDl\n"
                + "0CYRBHNjY34KtaEKMJYtrwiqW6BVFxW/enqVMhBG5AfV0NOIUyvNCpuNZsf1BXsi\n"
                + "O6+QSOWhgYkDgYYABADCaczsWr1CmsxEZTWMK4wtrHF2P15Ad5z03Qxed/hnVBMM\n"
                + "n4Y59o52d4/feUBki22MHFvndQHrzUc7oyEMI2wILAFIGFAqzszcPKD5d3WvMUPk\n"
                + "BdvuO/h/wrHYM/zZntloJ+0CBs2+RTADVxea+NFORt0AAwEBk0PALFKzC+ZgvpO1\n"
                + "Lg==";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "EC");

        Assert.assertNotNull(key);
        Assert.assertEquals("EC", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        String result = manager.createToken(key, SignatureAlgorithm.ES512, "subject", map, 1);
        Assert.assertNotNull(result);
    }

    @Test
    public void testCreateTokenOk2() throws CertificateException {

        String content = "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCzs/j3yORjHgSY\n"
                + "2Y1NHidRrRo+s+J4I6F0vmUWu+V7ltPM1XlJq3EhWBW9wqixY7ioLFTOFuDGBfSu\n"
                + "d5X+FSYP4G7fVLiiRebdGCpHa6YbHQAHcfrZcMfkL/PcR552NvQRnw259J1d8qtj\n"
                + "mPfukAqLApDksrNwUzH2TFq06qzbT1LZFeaPmptvl4vk3aE9j2P577sH7vR5Qmhj\n"
                + "a+xQiFMRR+m6AjpLxw93Hc6AZcOmeNTS/ZG/NDu+oxCUpbBLfvv6lDDfBrOj7Vap\n"
                + "bIEsXKvu3M9O7yL+OQaMo4kYFXyfBoJiOoqqi2avVCWFys/80oVS3d7xW2Ua8Fba\n"
                + "VfZG0d4ZACkSBQRoUiWMqGR+9LhoJYOQGrskBmmaMkbfVRmRyL9eqjQTBtB9wEoU\n"
                + "bRfij39Dlzk24U7hDVyyh8VJviv9j9rkxmbshBQfYawh6upAhxK4x9i96zbP3Sva\n"
                + "Xz8AesPF9eB2cbZ1XwWuT36Tu4Iy+1rFVF0nlP0XtYIy7htGzDydfuwUn6i2F1nT\n"
                + "EoOjxBLMM4NiDKl3Lp89/s8WmsQWjTUIxNY7/MSTpqWETFFfuP+lsd6ZdZo36wjB\n"
                + "581kvLUIPsj1p1bUQdyemPztsM0aikeanqTM9JPzGKGgCE+KNRGDVrFDR0Tsr7IX\n"
                + "uXYxQbNooBBFNKs5XhzZSXJ9XufijwIDAQABAoICADIIju42gdhS+Eayc9Qf7CSi\n"
                + "hKcmoIyApyiBBlZRFHDXqrriSPXJBSOaidsewqc5M6WnSiljV0vrRpf49csbilBr\n"
                + "VZNa3FlaCxBN9R+TilkMNwDbrFM0QoN3EnenfSg+3q+1UDYRNGt+8Fc3tPg4JKdV\n"
                + "nJAAbVN95nBEDBFJMb2SFWgZ3+rlyhdE449iYc1pChYBuFpaHrlQUw4zc0Vs32v1\n"
                + "UM8YZbDJiLXKl79KFjJYfDEOprDM00Gd1zT7+NzcSz4WWpEOJaAjqbhcXI7Ecp57\n"
                + "3kCE9oI/0GIB+l65RMxmHJFK6WbYj0uLqzLYKBalareKzNL4dmsMtbHuszY+oo5t\n"
                + "ngzQOCBM6PAK/9zE1zfezaMWHsnz5Ka/qiJ8Iib2LxuCyM0RgB+fXdm9cTYjw17r\n"
                + "0B+suwOa7lEd4pqqG65zELmJ58QSIxhmfKLGGiM7nU0MOxFbrZxyWB3dheA23Abr\n"
                + "hLxogjO9cqYg2N15cHFAapC6TSPL3UlBCrR3I86+9Fj+8FdDrJ8ElV6JP3u+D8d2\n"
                + "mg5WBGFFlVeDwcZt0HY3zyWTpfxudt5viu1NPHzsYrVcROpQrbjjElWGdeRqLup0\n"
                + "tSFmzwLnrsqpWd2I9zxF2BONzVYIrExCsueDAiSHf94lHCH890IOIuqOQf+ajvvT\n"
                + "rb9AnxgT5eyv6SoAsAZxAoIBAQDn+3Ii8Xssd37ybu1Nx94ne4FC0Q4ooSNfi2LE\n"
                + "cvPC5EwWo8T/ZnV4WIssySpDrD1MceSZ9W2/6Fof3wzz+rZa4jlLiNNVBYynf5lh\n"
                + "IB1UkFbrwKkNIthsUWGNX8x9X2HN8rpDnrxAGdlnMujbqigVt4gEYx1wGAIUiXgS\n"
                + "7OwrSkk7XZ6YyoaIgY2Egdpe8t2/wUwhrnpa00dh7OxvEOiR61LRgstsK67DJbHK\n"
                + "HDY+UhefAFzjXe2fRBf9vdGqjC7i7OeRw7ZCqEExyGTwdyrmWOQvslIfb+kJ+fwW\n"
                + "OAvDEuvtzaTbyqY0dGP+g9oxUfyA7URHF8kRcYUQw17aJDCnAoIBAQDGTuWe+IBK\n"
                + "S0j8tl5OvCuSdWgztmYiffixE6WrFoC5YP2Ii8Z4QJ1shr2T8HI32lam06y68ctT\n"
                + "YEg9pVQOGv28pnKCsR6WLEQ5Dt7za6SKZd1Xe9MOxojt8shRMfCfdbwrsYVHRHXa\n"
                + "b9CmQgKyMUMEj8rU91SdHT5k/sUED07Rq6JZZWEUjGk0AtYNT+6qDzNf8OAkGW2S\n"
                + "DxgWGJVV2MAua8wpkia/jOoEjFbHQ8ry51U2LVBYQ6XbUSmviX6O9pJYgyWydort\n"
                + "hHEK8EDSybhKxNB5Zp64bmz7ESs8PlzZY0mhHcVERnMFKt1P1gtLt8w+bc+bw4z9\n"
                + "hxUBgd/n99PZAoIBAEt5STcJLbPX5NtnL5mgryxVSEa+0UZytpl9NdMIOzprID41\n"
                + "ZgBaC1nuJMmbYT7HKOJYI7HbYauQItI/tW0jYnTLKSzkBS2iMpLENticpC5BD6Z/\n"
                + "9gAqGBOVnpFqW5NmluF0WRlq6YBJaKvkqlHdWFFIdt5GiOtRREv+NayinGuxLYY8\n"
                + "/T5klcSPscUsoilGBtM+RlCm/XPTTWQUuw+fhqsCzt0PGrPEuoUPHHrPFu7Lspeu\n"
                + "fIoUoxywAMYzHaXJGfAGd4i7De894ogZ1I1PmAt9XDAQahuEQ2NVi6iG73y2CUBD\n"
                + "KaHAmrZyL548s55cODSR/SbMHESqlEpR5eg+4f0CggEAJXg83Me5fdAxz0YqFZhq\n"
                + "Zzb15Gd/bt78gYDj2arb0aso3IcEji4vUJU49t4ExtbjbowqY/xR3cQggj1d33hs\n"
                + "HxwYIOeUju14SourxrS9F0VeCCymWXFb6BHqlaTpAUg+sMbPFwMxfX+JHhD073Rt\n"
                + "ZExDF/BPtYwUAQM+eKDn1Kgoedm0+Sv6qNAsX8GNp+ZNX8BkqY2AbYuakno8pUba\n"
                + "MSs/HU+3MJRQl2Fo+CewDit1p1Hyj2rgyMrSJI/HMP4X8s987PaHE4/lyBpTNUDW\n"
                + "KJJ9jaK9NL3wq5O35p8l7hFblSzJ3Devffd2b6JS6hClb9pR0u2lEzZV2r4Ob4cd\n"
                + "KQKCAQEA1fVw0LyFH1psO1EE4x2Cf6gvAPBsI3J4mCPt9V7mcXqMP3RwwJhKM2Pq\n"
                + "9jZGoSNoK6LE8tDZdRtbp9F6Lq3JpzPcpLrhgc+8EVAWuewPvahokQL5yp9VSpNI\n"
                + "phdhBq++cLKwK5L8oI7mJCnxFMIX8B5YQegLdYZSqdL7kwH7umYVE7vZx0ujK/YX\n"
                + "2p9/lvt+DCtk41ltlm99ugc66IpgpJ+kxU4GAt+ktRs/Cn294zYLLId42Sjs0T1P\n"
                + "/4pPazKoddoTe8F08Xfw6BYZr7OhpvmGup2v1c7fn70LbjSbp0ryqJ3UNa7XaunR\n"
                + "6uDlhEf4OvoIXpNSlQQUAcNfEhA/zg==";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "RSA");

        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        String result = manager.createToken(key, SignatureAlgorithm.RS512, "subject", map, 1);

        Assert.assertNotNull(result);
    }

    @Test(expected = CertificateException.class)
    public void testCreateTokenError() throws CertificateException {

        String content = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAdQ9nj+bY5G5XLDDl\n"
                + "0CYRBHNjY34KtaEKMJYtrwiqW6BVFxW/enqVMhBG5AfV0NOIUyvNCpuNZsf1BXsi\n"
                + "O6+QSOWhgYkDgYYABADCaczsWr1CmsxEZTWMK4wtrHF2P15Ad5z03Qxed/hnVBMM\n"
                + "n4Y59o52d4/feUBki22MHFvndQHrzUc7oyEMI2wILAFIGFAqzszcPKD5d3WvMUPk\n"
                + "BdvuO/h/wrHYM/zZntloJ+0CBs2+RTADVxea+NFORt0AAwEBk0PALFKzC+ZgvpO1\n"
                + "Lg==";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "EC");

        Assert.assertNotNull(key);
        Assert.assertEquals("EC", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        manager.createToken(key, SignatureAlgorithm.RS512, "subject", map, 1);
    }

    @Test(expected = CertificateException.class)
    public void testCreateTokenError2() throws CertificateException {

        String content = "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCzs/j3yORjHgSY\n"
                + "2Y1NHidRrRo+s+J4I6F0vmUWu+V7ltPM1XlJq3EhWBW9wqixY7ioLFTOFuDGBfSu\n"
                + "d5X+FSYP4G7fVLiiRebdGCpHa6YbHQAHcfrZcMfkL/PcR552NvQRnw259J1d8qtj\n"
                + "mPfukAqLApDksrNwUzH2TFq06qzbT1LZFeaPmptvl4vk3aE9j2P577sH7vR5Qmhj\n"
                + "a+xQiFMRR+m6AjpLxw93Hc6AZcOmeNTS/ZG/NDu+oxCUpbBLfvv6lDDfBrOj7Vap\n"
                + "bIEsXKvu3M9O7yL+OQaMo4kYFXyfBoJiOoqqi2avVCWFys/80oVS3d7xW2Ua8Fba\n"
                + "VfZG0d4ZACkSBQRoUiWMqGR+9LhoJYOQGrskBmmaMkbfVRmRyL9eqjQTBtB9wEoU\n"
                + "bRfij39Dlzk24U7hDVyyh8VJviv9j9rkxmbshBQfYawh6upAhxK4x9i96zbP3Sva\n"
                + "Xz8AesPF9eB2cbZ1XwWuT36Tu4Iy+1rFVF0nlP0XtYIy7htGzDydfuwUn6i2F1nT\n"
                + "EoOjxBLMM4NiDKl3Lp89/s8WmsQWjTUIxNY7/MSTpqWETFFfuP+lsd6ZdZo36wjB\n"
                + "581kvLUIPsj1p1bUQdyemPztsM0aikeanqTM9JPzGKGgCE+KNRGDVrFDR0Tsr7IX\n"
                + "uXYxQbNooBBFNKs5XhzZSXJ9XufijwIDAQABAoICADIIju42gdhS+Eayc9Qf7CSi\n"
                + "hKcmoIyApyiBBlZRFHDXqrriSPXJBSOaidsewqc5M6WnSiljV0vrRpf49csbilBr\n"
                + "VZNa3FlaCxBN9R+TilkMNwDbrFM0QoN3EnenfSg+3q+1UDYRNGt+8Fc3tPg4JKdV\n"
                + "nJAAbVN95nBEDBFJMb2SFWgZ3+rlyhdE449iYc1pChYBuFpaHrlQUw4zc0Vs32v1\n"
                + "UM8YZbDJiLXKl79KFjJYfDEOprDM00Gd1zT7+NzcSz4WWpEOJaAjqbhcXI7Ecp57\n"
                + "3kCE9oI/0GIB+l65RMxmHJFK6WbYj0uLqzLYKBalareKzNL4dmsMtbHuszY+oo5t\n"
                + "ngzQOCBM6PAK/9zE1zfezaMWHsnz5Ka/qiJ8Iib2LxuCyM0RgB+fXdm9cTYjw17r\n"
                + "0B+suwOa7lEd4pqqG65zELmJ58QSIxhmfKLGGiM7nU0MOxFbrZxyWB3dheA23Abr\n"
                + "hLxogjO9cqYg2N15cHFAapC6TSPL3UlBCrR3I86+9Fj+8FdDrJ8ElV6JP3u+D8d2\n"
                + "mg5WBGFFlVeDwcZt0HY3zyWTpfxudt5viu1NPHzsYrVcROpQrbjjElWGdeRqLup0\n"
                + "tSFmzwLnrsqpWd2I9zxF2BONzVYIrExCsueDAiSHf94lHCH890IOIuqOQf+ajvvT\n"
                + "rb9AnxgT5eyv6SoAsAZxAoIBAQDn+3Ii8Xssd37ybu1Nx94ne4FC0Q4ooSNfi2LE\n"
                + "cvPC5EwWo8T/ZnV4WIssySpDrD1MceSZ9W2/6Fof3wzz+rZa4jlLiNNVBYynf5lh\n"
                + "IB1UkFbrwKkNIthsUWGNX8x9X2HN8rpDnrxAGdlnMujbqigVt4gEYx1wGAIUiXgS\n"
                + "7OwrSkk7XZ6YyoaIgY2Egdpe8t2/wUwhrnpa00dh7OxvEOiR61LRgstsK67DJbHK\n"
                + "HDY+UhefAFzjXe2fRBf9vdGqjC7i7OeRw7ZCqEExyGTwdyrmWOQvslIfb+kJ+fwW\n"
                + "OAvDEuvtzaTbyqY0dGP+g9oxUfyA7URHF8kRcYUQw17aJDCnAoIBAQDGTuWe+IBK\n"
                + "S0j8tl5OvCuSdWgztmYiffixE6WrFoC5YP2Ii8Z4QJ1shr2T8HI32lam06y68ctT\n"
                + "YEg9pVQOGv28pnKCsR6WLEQ5Dt7za6SKZd1Xe9MOxojt8shRMfCfdbwrsYVHRHXa\n"
                + "b9CmQgKyMUMEj8rU91SdHT5k/sUED07Rq6JZZWEUjGk0AtYNT+6qDzNf8OAkGW2S\n"
                + "DxgWGJVV2MAua8wpkia/jOoEjFbHQ8ry51U2LVBYQ6XbUSmviX6O9pJYgyWydort\n"
                + "hHEK8EDSybhKxNB5Zp64bmz7ESs8PlzZY0mhHcVERnMFKt1P1gtLt8w+bc+bw4z9\n"
                + "hxUBgd/n99PZAoIBAEt5STcJLbPX5NtnL5mgryxVSEa+0UZytpl9NdMIOzprID41\n"
                + "ZgBaC1nuJMmbYT7HKOJYI7HbYauQItI/tW0jYnTLKSzkBS2iMpLENticpC5BD6Z/\n"
                + "9gAqGBOVnpFqW5NmluF0WRlq6YBJaKvkqlHdWFFIdt5GiOtRREv+NayinGuxLYY8\n"
                + "/T5klcSPscUsoilGBtM+RlCm/XPTTWQUuw+fhqsCzt0PGrPEuoUPHHrPFu7Lspeu\n"
                + "fIoUoxywAMYzHaXJGfAGd4i7De894ogZ1I1PmAt9XDAQahuEQ2NVi6iG73y2CUBD\n"
                + "KaHAmrZyL548s55cODSR/SbMHESqlEpR5eg+4f0CggEAJXg83Me5fdAxz0YqFZhq\n"
                + "Zzb15Gd/bt78gYDj2arb0aso3IcEji4vUJU49t4ExtbjbowqY/xR3cQggj1d33hs\n"
                + "HxwYIOeUju14SourxrS9F0VeCCymWXFb6BHqlaTpAUg+sMbPFwMxfX+JHhD073Rt\n"
                + "ZExDF/BPtYwUAQM+eKDn1Kgoedm0+Sv6qNAsX8GNp+ZNX8BkqY2AbYuakno8pUba\n"
                + "MSs/HU+3MJRQl2Fo+CewDit1p1Hyj2rgyMrSJI/HMP4X8s987PaHE4/lyBpTNUDW\n"
                + "KJJ9jaK9NL3wq5O35p8l7hFblSzJ3Devffd2b6JS6hClb9pR0u2lEzZV2r4Ob4cd\n"
                + "KQKCAQEA1fVw0LyFH1psO1EE4x2Cf6gvAPBsI3J4mCPt9V7mcXqMP3RwwJhKM2Pq\n"
                + "9jZGoSNoK6LE8tDZdRtbp9F6Lq3JpzPcpLrhgc+8EVAWuewPvahokQL5yp9VSpNI\n"
                + "phdhBq++cLKwK5L8oI7mJCnxFMIX8B5YQegLdYZSqdL7kwH7umYVE7vZx0ujK/YX\n"
                + "2p9/lvt+DCtk41ltlm99ugc66IpgpJ+kxU4GAt+ktRs/Cn294zYLLId42Sjs0T1P\n"
                + "/4pPazKoddoTe8F08Xfw6BYZr7OhpvmGup2v1c7fn70LbjSbp0ryqJ3UNa7XaunR\n"
                + "6uDlhEf4OvoIXpNSlQQUAcNfEhA/zg==";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "RSA");

        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        manager.createToken(key, SignatureAlgorithm.ES512, "subject", map, 1);
    }

    @Test
    public void testCreateToken_And_GetterSubjectOk() throws CertificateException {

        String content = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAdQ9nj+bY5G5XLDDl\n"
                + "0CYRBHNjY34KtaEKMJYtrwiqW6BVFxW/enqVMhBG5AfV0NOIUyvNCpuNZsf1BXsi\n"
                + "O6+QSOWhgYkDgYYABADCaczsWr1CmsxEZTWMK4wtrHF2P15Ad5z03Qxed/hnVBMM\n"
                + "n4Y59o52d4/feUBki22MHFvndQHrzUc7oyEMI2wILAFIGFAqzszcPKD5d3WvMUPk\n"
                + "BdvuO/h/wrHYM/zZntloJ+0CBs2+RTADVxea+NFORt0AAwEBk0PALFKzC+ZgvpO1\n"
                + "Lg==";

        String cert = "-----BEGIN CERTIFICATE-----\n"
                + "MIICdzCCAdgCFGPRSh9P7OH5n3WoqFQ/H3rTRIz2MAoGCCqGSM49BAMCMHoxCzAJ\n"
                + "BgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xpdGFuYTERMA8GA1UE\n"
                + "BwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYDVQQLDARMVERBMRcw\n"
                + "FQYDVQQDDA53d3cuYmFzZWRvcy5jbDAeFw0xOTA1MDYxNjM1MThaFw0xOTA2MDUx\n"
                + "NjM1MThaMHoxCzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xp\n"
                + "dGFuYTERMA8GA1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYD\n"
                + "VQQLDARMVERBMRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDCBmzAQBgcqhkjOPQIB\n"
                + "BgUrgQQAIwOBhgAEAMJpzOxavUKazERlNYwrjC2scXY/XkB3nPTdDF53+GdUEwyf\n"
                + "hjn2jnZ3j995QGSLbYwcW+d1AevNRzujIQwjbAgsAUgYUCrOzNw8oPl3da8xQ+QF\n"
                + "2+47+H/Csdgz/Nme2Wgn7QIGzb5FMANXF5r40U5G3QADAQGTQ8AsUrML5mC+k7Uu\n"
                + "MAoGCCqGSM49BAMCA4GMADCBiAJCAZDFVdEsbEdVb/LMAtQxSwdTfSDUQfIVfXWi\n"
                + "r7yzXOxbr/29neSkOBGLuI8/dyuOmXVrEHWktkAxTjYWMm8x110QAkIBy5hBB4vF\n"
                + "Uvb44B33SIxbTcgx61iuALL39Ej0/LcFZ1dZTOKrej75zkacMmDiX0MN9k76rT0v\n"
                + "WTLWDJzdaakmQEU=\n"
                + "-----END CERTIFICATE-----";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "EC");

        Assert.assertNotNull(key);
        Assert.assertEquals("EC", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        String result = manager.createToken(key, SignatureAlgorithm.ES512, "subject", map, 1);

        Assert.assertNotNull(result);

        streamPublicKey = new ByteArrayInputStream(cert.getBytes());
        PublicKey publicKey = certificate.getPublicKey(streamPublicKey);

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("EC", publicKey.getAlgorithm());

        Claims claims = manager.getClaims(result, publicKey);

        Assert.assertNotNull(claims);
        Assert.assertEquals("subject", claims.getSubject());
    }

    @Test
    public void testCreateToken_y_GetterSubjectOk2() throws CertificateException {

        String content = "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCzs/j3yORjHgSY\n"
                + "2Y1NHidRrRo+s+J4I6F0vmUWu+V7ltPM1XlJq3EhWBW9wqixY7ioLFTOFuDGBfSu\n"
                + "d5X+FSYP4G7fVLiiRebdGCpHa6YbHQAHcfrZcMfkL/PcR552NvQRnw259J1d8qtj\n"
                + "mPfukAqLApDksrNwUzH2TFq06qzbT1LZFeaPmptvl4vk3aE9j2P577sH7vR5Qmhj\n"
                + "a+xQiFMRR+m6AjpLxw93Hc6AZcOmeNTS/ZG/NDu+oxCUpbBLfvv6lDDfBrOj7Vap\n"
                + "bIEsXKvu3M9O7yL+OQaMo4kYFXyfBoJiOoqqi2avVCWFys/80oVS3d7xW2Ua8Fba\n"
                + "VfZG0d4ZACkSBQRoUiWMqGR+9LhoJYOQGrskBmmaMkbfVRmRyL9eqjQTBtB9wEoU\n"
                + "bRfij39Dlzk24U7hDVyyh8VJviv9j9rkxmbshBQfYawh6upAhxK4x9i96zbP3Sva\n"
                + "Xz8AesPF9eB2cbZ1XwWuT36Tu4Iy+1rFVF0nlP0XtYIy7htGzDydfuwUn6i2F1nT\n"
                + "EoOjxBLMM4NiDKl3Lp89/s8WmsQWjTUIxNY7/MSTpqWETFFfuP+lsd6ZdZo36wjB\n"
                + "581kvLUIPsj1p1bUQdyemPztsM0aikeanqTM9JPzGKGgCE+KNRGDVrFDR0Tsr7IX\n"
                + "uXYxQbNooBBFNKs5XhzZSXJ9XufijwIDAQABAoICADIIju42gdhS+Eayc9Qf7CSi\n"
                + "hKcmoIyApyiBBlZRFHDXqrriSPXJBSOaidsewqc5M6WnSiljV0vrRpf49csbilBr\n"
                + "VZNa3FlaCxBN9R+TilkMNwDbrFM0QoN3EnenfSg+3q+1UDYRNGt+8Fc3tPg4JKdV\n"
                + "nJAAbVN95nBEDBFJMb2SFWgZ3+rlyhdE449iYc1pChYBuFpaHrlQUw4zc0Vs32v1\n"
                + "UM8YZbDJiLXKl79KFjJYfDEOprDM00Gd1zT7+NzcSz4WWpEOJaAjqbhcXI7Ecp57\n"
                + "3kCE9oI/0GIB+l65RMxmHJFK6WbYj0uLqzLYKBalareKzNL4dmsMtbHuszY+oo5t\n"
                + "ngzQOCBM6PAK/9zE1zfezaMWHsnz5Ka/qiJ8Iib2LxuCyM0RgB+fXdm9cTYjw17r\n"
                + "0B+suwOa7lEd4pqqG65zELmJ58QSIxhmfKLGGiM7nU0MOxFbrZxyWB3dheA23Abr\n"
                + "hLxogjO9cqYg2N15cHFAapC6TSPL3UlBCrR3I86+9Fj+8FdDrJ8ElV6JP3u+D8d2\n"
                + "mg5WBGFFlVeDwcZt0HY3zyWTpfxudt5viu1NPHzsYrVcROpQrbjjElWGdeRqLup0\n"
                + "tSFmzwLnrsqpWd2I9zxF2BONzVYIrExCsueDAiSHf94lHCH890IOIuqOQf+ajvvT\n"
                + "rb9AnxgT5eyv6SoAsAZxAoIBAQDn+3Ii8Xssd37ybu1Nx94ne4FC0Q4ooSNfi2LE\n"
                + "cvPC5EwWo8T/ZnV4WIssySpDrD1MceSZ9W2/6Fof3wzz+rZa4jlLiNNVBYynf5lh\n"
                + "IB1UkFbrwKkNIthsUWGNX8x9X2HN8rpDnrxAGdlnMujbqigVt4gEYx1wGAIUiXgS\n"
                + "7OwrSkk7XZ6YyoaIgY2Egdpe8t2/wUwhrnpa00dh7OxvEOiR61LRgstsK67DJbHK\n"
                + "HDY+UhefAFzjXe2fRBf9vdGqjC7i7OeRw7ZCqEExyGTwdyrmWOQvslIfb+kJ+fwW\n"
                + "OAvDEuvtzaTbyqY0dGP+g9oxUfyA7URHF8kRcYUQw17aJDCnAoIBAQDGTuWe+IBK\n"
                + "S0j8tl5OvCuSdWgztmYiffixE6WrFoC5YP2Ii8Z4QJ1shr2T8HI32lam06y68ctT\n"
                + "YEg9pVQOGv28pnKCsR6WLEQ5Dt7za6SKZd1Xe9MOxojt8shRMfCfdbwrsYVHRHXa\n"
                + "b9CmQgKyMUMEj8rU91SdHT5k/sUED07Rq6JZZWEUjGk0AtYNT+6qDzNf8OAkGW2S\n"
                + "DxgWGJVV2MAua8wpkia/jOoEjFbHQ8ry51U2LVBYQ6XbUSmviX6O9pJYgyWydort\n"
                + "hHEK8EDSybhKxNB5Zp64bmz7ESs8PlzZY0mhHcVERnMFKt1P1gtLt8w+bc+bw4z9\n"
                + "hxUBgd/n99PZAoIBAEt5STcJLbPX5NtnL5mgryxVSEa+0UZytpl9NdMIOzprID41\n"
                + "ZgBaC1nuJMmbYT7HKOJYI7HbYauQItI/tW0jYnTLKSzkBS2iMpLENticpC5BD6Z/\n"
                + "9gAqGBOVnpFqW5NmluF0WRlq6YBJaKvkqlHdWFFIdt5GiOtRREv+NayinGuxLYY8\n"
                + "/T5klcSPscUsoilGBtM+RlCm/XPTTWQUuw+fhqsCzt0PGrPEuoUPHHrPFu7Lspeu\n"
                + "fIoUoxywAMYzHaXJGfAGd4i7De894ogZ1I1PmAt9XDAQahuEQ2NVi6iG73y2CUBD\n"
                + "KaHAmrZyL548s55cODSR/SbMHESqlEpR5eg+4f0CggEAJXg83Me5fdAxz0YqFZhq\n"
                + "Zzb15Gd/bt78gYDj2arb0aso3IcEji4vUJU49t4ExtbjbowqY/xR3cQggj1d33hs\n"
                + "HxwYIOeUju14SourxrS9F0VeCCymWXFb6BHqlaTpAUg+sMbPFwMxfX+JHhD073Rt\n"
                + "ZExDF/BPtYwUAQM+eKDn1Kgoedm0+Sv6qNAsX8GNp+ZNX8BkqY2AbYuakno8pUba\n"
                + "MSs/HU+3MJRQl2Fo+CewDit1p1Hyj2rgyMrSJI/HMP4X8s987PaHE4/lyBpTNUDW\n"
                + "KJJ9jaK9NL3wq5O35p8l7hFblSzJ3Devffd2b6JS6hClb9pR0u2lEzZV2r4Ob4cd\n"
                + "KQKCAQEA1fVw0LyFH1psO1EE4x2Cf6gvAPBsI3J4mCPt9V7mcXqMP3RwwJhKM2Pq\n"
                + "9jZGoSNoK6LE8tDZdRtbp9F6Lq3JpzPcpLrhgc+8EVAWuewPvahokQL5yp9VSpNI\n"
                + "phdhBq++cLKwK5L8oI7mJCnxFMIX8B5YQegLdYZSqdL7kwH7umYVE7vZx0ujK/YX\n"
                + "2p9/lvt+DCtk41ltlm99ugc66IpgpJ+kxU4GAt+ktRs/Cn294zYLLId42Sjs0T1P\n"
                + "/4pPazKoddoTe8F08Xfw6BYZr7OhpvmGup2v1c7fn70LbjSbp0ryqJ3UNa7XaunR\n"
                + "6uDlhEf4OvoIXpNSlQQUAcNfEhA/zg==";

        String cert = "-----BEGIN CERTIFICATE-----\n"
                + "MIIFezCCA2MCFAWfKkT+9vgtUjpAMAxSJkqGbT2SMA0GCSqGSIb3DQEBCwUAMHox\n"
                + "CzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xpdGFuYTERMA8G\n"
                + "A1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYDVQQLDARMVERB\n"
                + "MRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDAeFw0xOTA1MDYxNjM1MDVaFw0yMDA1\n"
                + "MDUxNjM1MDVaMHoxCzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9w\n"
                + "b2xpdGFuYTERMA8GA1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0w\n"
                + "CwYDVQQLDARMVERBMRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDCCAiIwDQYJKoZI\n"
                + "hvcNAQEBBQADggIPADCCAgoCggIBALOz+PfI5GMeBJjZjU0eJ1GtGj6z4ngjoXS+\n"
                + "ZRa75XuW08zVeUmrcSFYFb3CqLFjuKgsVM4W4MYF9K53lf4VJg/gbt9UuKJF5t0Y\n"
                + "KkdrphsdAAdx+tlwx+Qv89xHnnY29BGfDbn0nV3yq2OY9+6QCosCkOSys3BTMfZM\n"
                + "WrTqrNtPUtkV5o+am2+Xi+TdoT2PY/nvuwfu9HlCaGNr7FCIUxFH6boCOkvHD3cd\n"
                + "zoBlw6Z41NL9kb80O76jEJSlsEt++/qUMN8Gs6PtVqlsgSxcq+7cz07vIv45Boyj\n"
                + "iRgVfJ8GgmI6iqqLZq9UJYXKz/zShVLd3vFbZRrwVtpV9kbR3hkAKRIFBGhSJYyo\n"
                + "ZH70uGglg5AauyQGaZoyRt9VGZHIv16qNBMG0H3AShRtF+KPf0OXOTbhTuENXLKH\n"
                + "xUm+K/2P2uTGZuyEFB9hrCHq6kCHErjH2L3rNs/dK9pfPwB6w8X14HZxtnVfBa5P\n"
                + "fpO7gjL7WsVUXSeU/Re1gjLuG0bMPJ1+7BSfqLYXWdMSg6PEEswzg2IMqXcunz3+\n"
                + "zxaaxBaNNQjE1jv8xJOmpYRMUV+4/6Wx3pl1mjfrCMHnzWS8tQg+yPWnVtRB3J6Y\n"
                + "/O2wzRqKR5qepMz0k/MYoaAIT4o1EYNWsUNHROyvshe5djFBs2igEEU0qzleHNlJ\n"
                + "cn1e5+KPAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAI+EAqlCrQrJevRUGg58osFk\n"
                + "ERTjX33eSPtyIETNIRW3YFJhr5UV4EEsPJWk1laYxlEabJj+mLTmhNPYOMTF5cHN\n"
                + "sJMGLtzEnF3Mvm7jKDEZRaG/DGJNxPHw9GeF+hDd9LxNUbsiX1cR1v8ddo4cUDIh\n"
                + "L71gVhBYGYASsm/knac9DMKyefYt52FFcPNgW8HZ+BTRyGOwmabq4yYmV01NloOR\n"
                + "BUXhqZdR9t4tQHn+XS/ZIhJo7nGvzk627ZJQMUtufp/sPeXd2wrD6xiM51UXMkuK\n"
                + "hBL71KIf220a2erPNN3RFzit/X6aQq6y82wrZfl4DU79140QQrBU01AwJhsmCcms\n"
                + "zns/5wjkhFxgnXIlzrhFKuLQ92js5LjGFmu7wiiy6UtBvqpcXkXbM7eQGVT7YCPv\n"
                + "JQOXVLc0VeWzv11EY+P1IK1MdThWQgpF3C+Tn0D03950moFMrgAK46RochfCkcRS\n"
                + "dd8u0tx4gu/PeQ0IxAQXlfEYc3E1W3VKmQr+8x0scvf/ABDpgrvPCkPiPZP9oOmH\n"
                + "OMgB/I7H7fJzsxiwDNxP2PxMAK2CaawcBttkHpbrlx7UPLpwXAxkvQMAstzFUvYF\n"
                + "EgA5yKFkRKPXeH/lP5FbvIyPH1dSHQkerOPq0WxyMwKpfmmWwTxnCrcGvswN4Lyz\n"
                + "F03Y6TUpBO/gEm1+0Cv0\n"
                + "-----END CERTIFICATE-----";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "RSA");

        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        String result = manager.createToken(key, SignatureAlgorithm.RS512, "subject", map, 1);

        Assert.assertNotNull(result);

        streamPublicKey = new ByteArrayInputStream(cert.getBytes());
        PublicKey publicKey = certificate.getPublicKey(streamPublicKey);

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());

        Claims claims = manager.getClaims(result, publicKey);

        Assert.assertNotNull(claims);
        Assert.assertEquals("subject", claims.getSubject());
    }

    @Test
    public void testCreateToken_y_GetterSubjectOk3() throws CertificateException {

        String content = "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCzs/j3yORjHgSY\n"
                + "2Y1NHidRrRo+s+J4I6F0vmUWu+V7ltPM1XlJq3EhWBW9wqixY7ioLFTOFuDGBfSu\n"
                + "d5X+FSYP4G7fVLiiRebdGCpHa6YbHQAHcfrZcMfkL/PcR552NvQRnw259J1d8qtj\n"
                + "mPfukAqLApDksrNwUzH2TFq06qzbT1LZFeaPmptvl4vk3aE9j2P577sH7vR5Qmhj\n"
                + "a+xQiFMRR+m6AjpLxw93Hc6AZcOmeNTS/ZG/NDu+oxCUpbBLfvv6lDDfBrOj7Vap\n"
                + "bIEsXKvu3M9O7yL+OQaMo4kYFXyfBoJiOoqqi2avVCWFys/80oVS3d7xW2Ua8Fba\n"
                + "VfZG0d4ZACkSBQRoUiWMqGR+9LhoJYOQGrskBmmaMkbfVRmRyL9eqjQTBtB9wEoU\n"
                + "bRfij39Dlzk24U7hDVyyh8VJviv9j9rkxmbshBQfYawh6upAhxK4x9i96zbP3Sva\n"
                + "Xz8AesPF9eB2cbZ1XwWuT36Tu4Iy+1rFVF0nlP0XtYIy7htGzDydfuwUn6i2F1nT\n"
                + "EoOjxBLMM4NiDKl3Lp89/s8WmsQWjTUIxNY7/MSTpqWETFFfuP+lsd6ZdZo36wjB\n"
                + "581kvLUIPsj1p1bUQdyemPztsM0aikeanqTM9JPzGKGgCE+KNRGDVrFDR0Tsr7IX\n"
                + "uXYxQbNooBBFNKs5XhzZSXJ9XufijwIDAQABAoICADIIju42gdhS+Eayc9Qf7CSi\n"
                + "hKcmoIyApyiBBlZRFHDXqrriSPXJBSOaidsewqc5M6WnSiljV0vrRpf49csbilBr\n"
                + "VZNa3FlaCxBN9R+TilkMNwDbrFM0QoN3EnenfSg+3q+1UDYRNGt+8Fc3tPg4JKdV\n"
                + "nJAAbVN95nBEDBFJMb2SFWgZ3+rlyhdE449iYc1pChYBuFpaHrlQUw4zc0Vs32v1\n"
                + "UM8YZbDJiLXKl79KFjJYfDEOprDM00Gd1zT7+NzcSz4WWpEOJaAjqbhcXI7Ecp57\n"
                + "3kCE9oI/0GIB+l65RMxmHJFK6WbYj0uLqzLYKBalareKzNL4dmsMtbHuszY+oo5t\n"
                + "ngzQOCBM6PAK/9zE1zfezaMWHsnz5Ka/qiJ8Iib2LxuCyM0RgB+fXdm9cTYjw17r\n"
                + "0B+suwOa7lEd4pqqG65zELmJ58QSIxhmfKLGGiM7nU0MOxFbrZxyWB3dheA23Abr\n"
                + "hLxogjO9cqYg2N15cHFAapC6TSPL3UlBCrR3I86+9Fj+8FdDrJ8ElV6JP3u+D8d2\n"
                + "mg5WBGFFlVeDwcZt0HY3zyWTpfxudt5viu1NPHzsYrVcROpQrbjjElWGdeRqLup0\n"
                + "tSFmzwLnrsqpWd2I9zxF2BONzVYIrExCsueDAiSHf94lHCH890IOIuqOQf+ajvvT\n"
                + "rb9AnxgT5eyv6SoAsAZxAoIBAQDn+3Ii8Xssd37ybu1Nx94ne4FC0Q4ooSNfi2LE\n"
                + "cvPC5EwWo8T/ZnV4WIssySpDrD1MceSZ9W2/6Fof3wzz+rZa4jlLiNNVBYynf5lh\n"
                + "IB1UkFbrwKkNIthsUWGNX8x9X2HN8rpDnrxAGdlnMujbqigVt4gEYx1wGAIUiXgS\n"
                + "7OwrSkk7XZ6YyoaIgY2Egdpe8t2/wUwhrnpa00dh7OxvEOiR61LRgstsK67DJbHK\n"
                + "HDY+UhefAFzjXe2fRBf9vdGqjC7i7OeRw7ZCqEExyGTwdyrmWOQvslIfb+kJ+fwW\n"
                + "OAvDEuvtzaTbyqY0dGP+g9oxUfyA7URHF8kRcYUQw17aJDCnAoIBAQDGTuWe+IBK\n"
                + "S0j8tl5OvCuSdWgztmYiffixE6WrFoC5YP2Ii8Z4QJ1shr2T8HI32lam06y68ctT\n"
                + "YEg9pVQOGv28pnKCsR6WLEQ5Dt7za6SKZd1Xe9MOxojt8shRMfCfdbwrsYVHRHXa\n"
                + "b9CmQgKyMUMEj8rU91SdHT5k/sUED07Rq6JZZWEUjGk0AtYNT+6qDzNf8OAkGW2S\n"
                + "DxgWGJVV2MAua8wpkia/jOoEjFbHQ8ry51U2LVBYQ6XbUSmviX6O9pJYgyWydort\n"
                + "hHEK8EDSybhKxNB5Zp64bmz7ESs8PlzZY0mhHcVERnMFKt1P1gtLt8w+bc+bw4z9\n"
                + "hxUBgd/n99PZAoIBAEt5STcJLbPX5NtnL5mgryxVSEa+0UZytpl9NdMIOzprID41\n"
                + "ZgBaC1nuJMmbYT7HKOJYI7HbYauQItI/tW0jYnTLKSzkBS2iMpLENticpC5BD6Z/\n"
                + "9gAqGBOVnpFqW5NmluF0WRlq6YBJaKvkqlHdWFFIdt5GiOtRREv+NayinGuxLYY8\n"
                + "/T5klcSPscUsoilGBtM+RlCm/XPTTWQUuw+fhqsCzt0PGrPEuoUPHHrPFu7Lspeu\n"
                + "fIoUoxywAMYzHaXJGfAGd4i7De894ogZ1I1PmAt9XDAQahuEQ2NVi6iG73y2CUBD\n"
                + "KaHAmrZyL548s55cODSR/SbMHESqlEpR5eg+4f0CggEAJXg83Me5fdAxz0YqFZhq\n"
                + "Zzb15Gd/bt78gYDj2arb0aso3IcEji4vUJU49t4ExtbjbowqY/xR3cQggj1d33hs\n"
                + "HxwYIOeUju14SourxrS9F0VeCCymWXFb6BHqlaTpAUg+sMbPFwMxfX+JHhD073Rt\n"
                + "ZExDF/BPtYwUAQM+eKDn1Kgoedm0+Sv6qNAsX8GNp+ZNX8BkqY2AbYuakno8pUba\n"
                + "MSs/HU+3MJRQl2Fo+CewDit1p1Hyj2rgyMrSJI/HMP4X8s987PaHE4/lyBpTNUDW\n"
                + "KJJ9jaK9NL3wq5O35p8l7hFblSzJ3Devffd2b6JS6hClb9pR0u2lEzZV2r4Ob4cd\n"
                + "KQKCAQEA1fVw0LyFH1psO1EE4x2Cf6gvAPBsI3J4mCPt9V7mcXqMP3RwwJhKM2Pq\n"
                + "9jZGoSNoK6LE8tDZdRtbp9F6Lq3JpzPcpLrhgc+8EVAWuewPvahokQL5yp9VSpNI\n"
                + "phdhBq++cLKwK5L8oI7mJCnxFMIX8B5YQegLdYZSqdL7kwH7umYVE7vZx0ujK/YX\n"
                + "2p9/lvt+DCtk41ltlm99ugc66IpgpJ+kxU4GAt+ktRs/Cn294zYLLId42Sjs0T1P\n"
                + "/4pPazKoddoTe8F08Xfw6BYZr7OhpvmGup2v1c7fn70LbjSbp0ryqJ3UNa7XaunR\n"
                + "6uDlhEf4OvoIXpNSlQQUAcNfEhA/zg==";

        String cert = "-----BEGIN CERTIFICATE-----\n"
                + "MIIFezCCA2MCFAWfKkT+9vgtUjpAMAxSJkqGbT2SMA0GCSqGSIb3DQEBCwUAMHox\n"
                + "CzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9wb2xpdGFuYTERMA8G\n"
                + "A1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0wCwYDVQQLDARMVERB\n"
                + "MRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDAeFw0xOTA1MDYxNjM1MDVaFw0yMDA1\n"
                + "MDUxNjM1MDVaMHoxCzAJBgNVBAYTAkNMMR0wGwYDVQQIDBRSZWdpb24gTWV0cm9w\n"
                + "b2xpdGFuYTERMA8GA1UEBwwIU2FudGlhZ28xETAPBgNVBAoMCEJhc2UgRG9zMQ0w\n"
                + "CwYDVQQLDARMVERBMRcwFQYDVQQDDA53d3cuYmFzZWRvcy5jbDCCAiIwDQYJKoZI\n"
                + "hvcNAQEBBQADggIPADCCAgoCggIBALOz+PfI5GMeBJjZjU0eJ1GtGj6z4ngjoXS+\n"
                + "ZRa75XuW08zVeUmrcSFYFb3CqLFjuKgsVM4W4MYF9K53lf4VJg/gbt9UuKJF5t0Y\n"
                + "KkdrphsdAAdx+tlwx+Qv89xHnnY29BGfDbn0nV3yq2OY9+6QCosCkOSys3BTMfZM\n"
                + "WrTqrNtPUtkV5o+am2+Xi+TdoT2PY/nvuwfu9HlCaGNr7FCIUxFH6boCOkvHD3cd\n"
                + "zoBlw6Z41NL9kb80O76jEJSlsEt++/qUMN8Gs6PtVqlsgSxcq+7cz07vIv45Boyj\n"
                + "iRgVfJ8GgmI6iqqLZq9UJYXKz/zShVLd3vFbZRrwVtpV9kbR3hkAKRIFBGhSJYyo\n"
                + "ZH70uGglg5AauyQGaZoyRt9VGZHIv16qNBMG0H3AShRtF+KPf0OXOTbhTuENXLKH\n"
                + "xUm+K/2P2uTGZuyEFB9hrCHq6kCHErjH2L3rNs/dK9pfPwB6w8X14HZxtnVfBa5P\n"
                + "fpO7gjL7WsVUXSeU/Re1gjLuG0bMPJ1+7BSfqLYXWdMSg6PEEswzg2IMqXcunz3+\n"
                + "zxaaxBaNNQjE1jv8xJOmpYRMUV+4/6Wx3pl1mjfrCMHnzWS8tQg+yPWnVtRB3J6Y\n"
                + "/O2wzRqKR5qepMz0k/MYoaAIT4o1EYNWsUNHROyvshe5djFBs2igEEU0qzleHNlJ\n"
                + "cn1e5+KPAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAI+EAqlCrQrJevRUGg58osFk\n"
                + "ERTjX33eSPtyIETNIRW3YFJhr5UV4EEsPJWk1laYxlEabJj+mLTmhNPYOMTF5cHN\n"
                + "sJMGLtzEnF3Mvm7jKDEZRaG/DGJNxPHw9GeF+hDd9LxNUbsiX1cR1v8ddo4cUDIh\n"
                + "L71gVhBYGYASsm/knac9DMKyefYt52FFcPNgW8HZ+BTRyGOwmabq4yYmV01NloOR\n"
                + "BUXhqZdR9t4tQHn+XS/ZIhJo7nGvzk627ZJQMUtufp/sPeXd2wrD6xiM51UXMkuK\n"
                + "hBL71KIf220a2erPNN3RFzit/X6aQq6y82wrZfl4DU79140QQrBU01AwJhsmCcms\n"
                + "zns/5wjkhFxgnXIlzrhFKuLQ92js5LjGFmu7wiiy6UtBvqpcXkXbM7eQGVT7YCPv\n"
                + "JQOXVLc0VeWzv11EY+P1IK1MdThWQgpF3C+Tn0D03950moFMrgAK46RochfCkcRS\n"
                + "dd8u0tx4gu/PeQ0IxAQXlfEYc3E1W3VKmQr+8x0scvf/ABDpgrvPCkPiPZP9oOmH\n"
                + "OMgB/I7H7fJzsxiwDNxP2PxMAK2CaawcBttkHpbrlx7UPLpwXAxkvQMAstzFUvYF\n"
                + "EgA5yKFkRKPXeH/lP5FbvIyPH1dSHQkerOPq0WxyMwKpfmmWwTxnCrcGvswN4Lyz\n"
                + "F03Y6TUpBO/gEm1+0Cv0\n"
                + "-----END CERTIFICATE-----";

        streamPrivateKey = new ByteArrayInputStream(content.getBytes());
        PrivateKey key = certificate.getPrivateKey(streamPrivateKey, "RSA");

        Assert.assertNotNull(key);
        Assert.assertEquals("RSA", key.getAlgorithm());

        Map<String, Object> map = new HashMap<>();

        String result = manager.createToken(key, SignatureAlgorithm.RS512, "subject", map, 0);

        Assert.assertNotNull(result);

        streamPublicKey = new ByteArrayInputStream(cert.getBytes());
        PublicKey publicKey = certificate.getPublicKey(streamPublicKey);

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());

        Claims claims = manager.getClaims(result, publicKey);

        Assert.assertNotNull(claims);
        Assert.assertEquals("subject", claims.getSubject());
    }

    @Test(expected = CertificateException.class)
    public void testGetClaimsError() throws CertificateException {
        manager.getClaims(null, null);
    }

}
