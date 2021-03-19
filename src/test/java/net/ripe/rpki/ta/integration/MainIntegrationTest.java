/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.ta.integration;


import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.ta.KeyStore;
import net.ripe.rpki.ta.Main;
import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.EnvStub;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY;
import static net.ripe.rpki.ta.Main.EXIT_ERROR_2;
import static net.ripe.rpki.ta.Main.EXIT_OK;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class MainIntegrationTest extends AbstractIntegrationTest {

    private static String taXmlPath;
    private static String talPath;

    @Rule
    public final TemporaryFolder tmp = new TemporaryFolder();

    @Before
    public void setUp() throws Exception {
        final File tmpDir = tmp.newFolder();
        EnvStub._testConfig.setPersistentStorageDir(tmpDir.getAbsolutePath());

        taXmlPath = new File(tmpDir.getAbsolutePath(), "ta.xml").getAbsolutePath();
        talPath = new File(tmpDir.getAbsolutePath(), "test.tal").getAbsolutePath();
        deleteFile(taXmlPath);
        deleteFile(talPath);
    }

    @After
    public void teardown() {
        deleteFile(taXmlPath);
        deleteFile(talPath);
    }

    @Test
    public void initialize_local_should_write_ta_xml() {
        assertThat(run("--initialise --env=test").exitCode, is(0));
        assertThat(readFile(taXmlPath), containsString("<TA>"));
    }

    @Test
    public void generate_certificate_should_rewrite_state() {
        assertThat(run("--initialise --env=test").exitCode, is(0));
        final String taXml = readFile(taXmlPath);
        assertThat(run("--generate-ta-certificate --env=test").exitCode, is(0));
        final String taXmlRegenerated = readFile(taXmlPath);
        assertNotEquals(taXml, taXmlRegenerated);
    }

    @Ignore ("We do not need to initialise from the old. This can go...")
    @Test
    public void print_ta() {
        run("--initialise-from-old=./src/test/resources/ta-legacy.xml --env=test");

        run("--print-tal="+ talPath +" --env=test");

        assertThat(readFile(talPath), equalTo(
                "rsync://localhost:10873/ta/RIPE-NCC-TA-TEST.cer\n\n"+
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIXenLOBfyo7cOnm4mGKmYxsoWCp28dw3XJAoZNWPDK8i9MxYACpwfz7bj" +
                        "yGma1BWPBJuievNd6nriFI+3WG+wt2bnO2ZmiLenCwMtm8bu7BeldpWRwlAnRp4t4IL6sZ7T9bF+4sTrv1qiEANqam0mhtLtUfbWXV" +
                        "5Z4mjgnNur7fJH2lIOm7Oc2/tok1rid8WsPe18zuvgwA3M0fKQ/Oa4SMXKnHr3fg2cHAm1cfEEvhMKa3rUAvsKGVEYeTJNg6rh3IRn" +
                        "jWhZ8GmE1ywl/9qMa2z4YsUi9Bx9U+/zMS8qpJn/q6XBbZ8XYTTFvSWfXd6b82jSfABa4ukIDCUF/QFwIDAQAB\n")
        );
    }

    @Ignore ("We do not need to initialise from the old. This can go...")
    @Test
    public void generate_ta_certificate() throws Exception {
        final Main.Exit exit = run("--initialise-from-old=./src/test/resources/ta-legacy.xml --env=test");
        assertEquals(0, exit.exitCode);

        final TAState taState = reloadTaState();
        assertEquals(BigInteger.valueOf(29L), taState.getLastIssuedCertificateSerial());
    }

    @Test
    public void process_request() throws Exception {
        assertEquals(0, run("--initialise --env=test").exitCode);

        final File tmpResponses = Files.createTempDir();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");
        
        assertEquals(0,
            run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                      "--response=" + response.getAbsolutePath() + " --env=test").exitCode);

        final TAState taState1 = reloadTaState();
        assertEquals(BigInteger.valueOf(4L), taState1.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastMftSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastCrlSerial());
        assertEquals(1, taState1.getSignedProductionCertificates().size());
        assertEquals(1, taState1.getSignedManifests().size());
        assertNull(taState1.getCrl().getCrl().getRevokedCertificates());

        assertEquals(0,
            run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                      "--response=" + response.getAbsolutePath() + " --env=test").exitCode);
        final TAState taState2 = reloadTaState();
        assertEquals(BigInteger.valueOf(6L), taState2.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastMftSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastCrlSerial());
        assertEquals(2, taState2.getSignedProductionCertificates().size());
        assertEquals(2, taState2.getSignedManifests().size());
        assertEquals(2, taState2.getCrl().getCrl().getRevokedCertificates().size());

        assertEquals(0,
            run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                      "--response=" + response.getAbsolutePath() + " --env=test").exitCode);
        final TAState taState3 = reloadTaState();
        assertEquals(BigInteger.valueOf(8L), taState3.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastMftSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastCrlSerial());

        // TODO only one certificate must be current
        assertEquals(3, taState3.getSignedProductionCertificates().size());
        assertEquals(3, taState3.getSignedManifests().size());

        assertEquals(4, taState3.getCrl().getCrl().getRevokedCertificates().size());
    }


    @Test
    public void process_request_make_sure_ta_certificate_reissued_for_different_url() throws Exception {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final File tmpResponses = Files.createTempDir();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        assertEquals(0, run("--request=./src/test/resources/ta-request-changed-rrdp-url.xml " +
            "--response=" + response.getAbsolutePath() +
            " --force-new-ta-certificate --env=test").exitCode);

        final TAState taStateAfterRrdpChange = reloadTaState();

        assertNotNull(taStateAfterRrdpChange);

        final X509ResourceCertificate taCertAfter = getTaCertificate(taStateAfterRrdpChange);
        assertNotEquals(taCertBefore.getSerialNumber(), taCertAfter.getSerialNumber());

        assertEquals(URI.create("https://localhost:7788/notification.xml"), getNotifyUrl(taCertBefore));
        assertEquals(URI.create("https://new-url.ripe.net/notification.xml"), getNotifyUrl(taCertAfter));

        assertEquals(taCertBefore.getResources(), taCertAfter.getResources());
        assertEquals(taCertBefore.getPublicKey(), taCertAfter.getPublicKey());
    }

    @Test
    public void process_request_do_not_reissue_ta_certificate_without_force_option() throws Exception {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final File tmpResponses = Files.createTempDir();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        final Main.Exit run = run("--request=./src/test/resources/ta-request-changed-rrdp-url.xml " +
            "--response=" + response.getAbsolutePath() +
            " --env=test");
        assertEquals(EXIT_ERROR_2, run.exitCode);
        assertTrue(run.stderr.contains("The following problem occurred: " +
            "TA certificate has to be re-issued: Different notification.xml URL, " +
            "request has 'https://new-url.ripe.net/notification.xml', config has 'https://localhost:7788/notification.xml', " +
            "bailing out. Provide force-new-ta-certificate option to force TA certificate re-issue."));
    }

    @Test
    public void test_export_ta_certificate() {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final Main.Exit run = run("--export-ta-certificate="+ talPath +" --env=test");
        assertEquals(EXIT_OK, run.exitCode);

        assertThat(readFile(talPath), notNullValue());
    }

    @Test
    public void test_print_ta_certificate() {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final Main.Exit run = run("--print-tal="+ talPath +" --env=test");
        assertEquals(EXIT_OK, run.exitCode);

        assertThat(readFile(talPath), notNullValue());
    }

    private java.net.URI getNotifyUrl(X509ResourceCertificate certificate) {
        final X509CertificateInformationAccessDescriptor[] authorityInformationAccess = certificate.getSubjectInformationAccess();
        if (authorityInformationAccess == null) {
            return null;
        }
        for (X509CertificateInformationAccessDescriptor descriptor : authorityInformationAccess) {
            if (ID_AD_RPKI_NOTIFY.equals(descriptor.getMethod())) {
                return descriptor.getLocation();
            }
        }
        return null;
    }

    private X509ResourceCertificate getTaCertificate(TAState taState) throws Exception {
        return KeyStore.of(taState.getConfig()).decode(taState.getEncoded()).getRight();
    }

    private TAState reloadTaState() throws Exception {
        return new TA(EnvStub.test()).loadTAState();
    }


}
