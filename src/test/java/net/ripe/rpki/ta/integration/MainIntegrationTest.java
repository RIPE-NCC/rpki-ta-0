package net.ripe.rpki.ta.integration;


import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.ta.KeyStore;
import net.ripe.rpki.ta.Main;
import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.EnvStub;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY;
import static net.ripe.rpki.ta.Main.EXIT_ERROR_2;
import static net.ripe.rpki.ta.Main.EXIT_OK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MainIntegrationTest extends AbstractIntegrationTest {

    private static String taXmlPath;
    private static String talPath;

    @BeforeEach
    public void setUp(@TempDir Path tmpDir) throws Exception {
        final Path absolutePath = tmpDir.toAbsolutePath();
        EnvStub._testConfig.setPersistentStorageDir(absolutePath.toString());

        taXmlPath = absolutePath.resolve("ta.xml").toString();
        talPath = absolutePath.resolve("test.tal").toString();
        deleteFile(taXmlPath);
        deleteFile(talPath);
    }

    @AfterEach
    public void teardown() {
        deleteFile(taXmlPath);
        deleteFile(talPath);
    }

    @Test
    public void test_initialize_local_should_write_ta_xml() {
        assertThat(run("--initialise --env=test").exitCode).isZero();
        assertThat(readFile(taXmlPath)).contains("<TA>");
    }

    @Test
    public void test_generate_certificate_should_rewrite_state() {
        assertThat(run("--initialise --env=test").exitCode).isZero();
        final String taXml = readFile(taXmlPath);
        assertThat(run("--generate-ta-certificate --env=test").exitCode).isZero();
        final String taXmlRegenerated = readFile(taXmlPath);
        assertThat(taXmlRegenerated).isNotEqualTo(taXml);
    }

    @Test
    public void test_process_request() throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();

        final File tmpResponses = Files.createTempDirectory("process_request").toFile();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");
        
        assertThat(run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                      "--response=" + response.getAbsolutePath() + " --env=test").exitCode).isZero();

        final TAState taState1 = reloadTaState();
        assertEquals(BigInteger.valueOf(4L), taState1.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastMftSerial());
        assertEquals(BigInteger.valueOf(1L), taState1.getLastCrlSerial());
        assertEquals(1, taState1.getSignedProductionCertificates().size());
        assertEquals(1, taState1.getSignedManifests().size());
        assertThat(taState1.getCrl().getCrl().getRevokedCertificates()).isNull();

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
    public void test_process_request_make_sure_ta_certificate_reissued_for_different_url() throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();
        assertThat(run("--generate-ta-certificate --env=test").exitCode).isZero();

        final File tmpResponses = Files.createTempDirectory("process_request_make_sure_ta_certificate_reissued_for_different_url").toFile();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        assertThat(
                run("--request=./src/test/resources/ta-request-changed-rrdp-url.xml " +
            "--response=" + response.getAbsolutePath() +
            " --force-new-ta-certificate --env=test").exitCode).isZero();

        final TAState taStateAfterRrdpChange = reloadTaState();

        assertThat(taStateAfterRrdpChange).isNotNull();

        final X509ResourceCertificate taCertAfter = getTaCertificate(taStateAfterRrdpChange);
        assertThat(taCertBefore.getSerialNumber()).isNotEqualTo(taCertAfter.getSerialNumber());

        assertEquals(URI.create("https://localhost:7788/notification.xml"), getNotifyUrl(taCertBefore));
        assertEquals(URI.create("https://new-url.ripe.net/notification.xml"), getNotifyUrl(taCertAfter));

        assertEquals(taCertBefore.getResources(), taCertAfter.getResources());
        assertEquals(taCertBefore.getPublicKey(), taCertAfter.getPublicKey());
    }

    @Test
    public void test_process_request_do_not_reissue_ta_certificate_without_force_option() throws Exception {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final File tmpResponses = Files.createTempDirectory("process_request_do_not_reissue_ta_certificate_without_force_option").toFile();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        final Main.Exit run = run("--request=./src/test/resources/ta-request-changed-rrdp-url.xml " +
            "--response=" + response.getAbsolutePath() +
            " --env=test");
        assertEquals(EXIT_ERROR_2, run.exitCode);
        assertThat(run.stderr).contains("The following problem occurred: " +
            "TA certificate has to be re-issued: Different notification.xml URL, " +
            "request has 'https://new-url.ripe.net/notification.xml', config has 'https://localhost:7788/notification.xml', " +
            "bailing out. Provide force-new-ta-certificate option to force TA certificate re-issue.");
    }

    @Test
    public void test_export_ta_certificate() {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final Main.Exit run = run("--export-ta-certificate="+ talPath +" --env=test");
        assertThat(run.exitCode).isEqualTo(EXIT_OK);

        assertThat(readFile(talPath)).isNotEmpty();
    }

    @Test
    public void test_print_ta_certificate() {
        assertEquals(0, run("--initialise --env=test").exitCode);
        assertEquals(0, run("--generate-ta-certificate --env=test").exitCode);

        final Main.Exit run = run("--print-tal="+ talPath +" --env=test");
        assertThat(run.exitCode).isEqualTo(EXIT_OK);

        assertThat(readFile(talPath)).isNotEmpty();
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
