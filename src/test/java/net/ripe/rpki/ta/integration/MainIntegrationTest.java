package net.ripe.rpki.ta.integration;


import com.google.common.base.Predicates;
import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.ta.KeyStore;
import net.ripe.rpki.ta.Main;
import net.ripe.rpki.ta.TA;
import net.ripe.rpki.ta.config.EnvStub;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedObjectTracker;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;
import org.joda.time.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY;
import static net.ripe.rpki.ta.Main.EXIT_ERROR_2;
import static net.ripe.rpki.ta.Main.EXIT_OK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
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
    public void test_initialise_local_should_write_ta_xml() {
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
        // TA certificate will be reissued, so serial numbers will be incremented
        assertEquals(BigInteger.valueOf(7L), taState2.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastMftSerial());
        assertEquals(BigInteger.valueOf(2L), taState2.getLastCrlSerial());
        assertEquals(2, taState2.getSignedProductionCertificates().size());
        assertEquals(2, taState2.getSignedManifests().size());
        assertEquals(2, taState2.getCrl().getCrl().getRevokedCertificates().size());

        assertEquals(0,
            run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                      "--response=" + response.getAbsolutePath() + " --env=test").exitCode);
        final TAState taState3 = reloadTaState();
        // TA certificate will be re-issued simply because of the -force-new-ta-certificate
        assertEquals(BigInteger.valueOf(10L), taState3.getLastIssuedCertificateSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastMftSerial());
        assertEquals(BigInteger.valueOf(3L), taState3.getLastCrlSerial());

        assertEquals(3, taState3.getSignedProductionCertificates().size());
        assertThat(taState3.getSignedProductionCertificates())
                .filteredOn(crt -> !crt.isRevoked())
                .hasSize(1);
        assertEquals(3, taState3.getSignedManifests().size());

        assertEquals(4, taState3.getCrl().getCrl().getRevokedCertificates().size());
    }

    @Test
    public void test_process_request_revokes_manifest_ee_certificates() throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();

        final File tmpResponses = Files.createTempDirectory("process_request").toFile();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        assertThat(run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                "--response=" + response.getAbsolutePath() + " --env=test").exitCode).isZero();

        final TAState initialState = reloadTaState();
        assertEquals(0,
                run("--request=./src/test/resources/ta-request.xml " +
                        "--response=" + response.getAbsolutePath() + " --env=test").exitCode);
        final TAState secondState = reloadTaState();

        // The EE certs from first state should be revoked
        final List<X509Certificate> manifestEE = initialState.getSignedManifests().stream()
                .map(SignedManifest::getManifest)
                .map(ManifestCms::getCertificate)
                .map(X509ResourceCertificate::getCertificate)
                .collect(Collectors.toList());
        final X509Crl secondCrl = secondState.getCrl();

        assertThat(manifestEE).allMatch(secondCrl::isRevoked);
    }

    /**
     * Check the manifest and CRL invariants that should hold.
     *   * manifest and CRL validity period match
     *   * no CRL entries are after thisUpdate
     * @param state
     */
    private void validateManifestAndCrlInvariants(TAState state) {
        // sanity check on config
        assertThat(state.getConfig().getMinimumValidityPeriod().toDurationFrom(Instant.now()).toDuration()).isGreaterThan(Duration.standardDays(1));

        var crl = state.getCrl();
        if (crl != null) {
            // Check CRL lifetime is at least the minimum period
            assertThat(crl.getThisUpdateTime().plus(state.getConfig().getMinimumValidityPeriod())).isLessThanOrEqualTo(crl.getNextUpdateTime());
            // check that CRL does not contain entries in the future
            crl.getRevokedCertificates().forEach(revokedEntry -> {
                assertThat(revokedEntry.getRevocationDateTime()).isLessThanOrEqualTo(crl.getThisUpdateTime());
            });
        }

        /**
         * Check the manifest(s) against CRL validity. There are two parts here:
         *   * Manifest thisUpdate/nextUpdate
         *   * EE cert validity
         */

        // check manifest against CRL validity
        state.getSignedManifests().forEach(manifestWrapper -> {
            var manifest = manifestWrapper.getManifest();
            assertThat(manifestWrapper.getNotValidAfter()).isEqualTo(manifest.getNotValidAfter());

            // thisUpdate/nextUpdate
            assertThat(manifest.getThisUpdateTime()).isEqualTo(crl.getThisUpdateTime());
            assertThat(manifest.getNextUpdateTime()).isEqualTo(crl.getNextUpdateTime());

            // EE validity
            var eeValidityPeriod = manifest.getValidityPeriod();

            assertThat(eeValidityPeriod.getNotValidBefore()).isEqualTo(crl.getThisUpdateTime());
            assertThat(eeValidityPeriod.getNotValidAfter()).isEqualTo(crl.getNextUpdateTime());
        });
    }

    @Test
    public void test_process_request_reissue_revokes_old_cert() throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();

        final File tmpResponses = Files.createTempDirectory("process_request").toFile();
        tmpResponses.deleteOnExit();
        final File response = new File(tmpResponses.getAbsolutePath(), "response.xml");

        assertThat(run("--request=./src/test/resources/ta-request.xml --force-new-ta-certificate " +
                "--response=" + response.getAbsolutePath() + " --env=test").exitCode).isZero();

        final TAState initialState = reloadTaState();
        assertEquals(0,
                run("--request=./src/test/resources/ta-request.xml " +
                        "--response=" + response.getAbsolutePath() + " --env=test").exitCode);
        final TAState secondState = reloadTaState();

        // The resource certificate from initial state should be revoked.
        final X509Crl secondCrl = secondState.getCrl();

        assertThat(initialState.getSignedProductionCertificates())
                .map(SignedResourceCertificate::getResourceCertificate)
                .map(X509ResourceCertificate::getCertificate)
                .allMatch(secondCrl::isRevoked);
    }

    /**
     * Initialise this with one environment, try signing a request from a different environment.
     *
     * TA0 must reject this.
     * <emph>Note that if we force the re-issuance of a certificate, this will be overridden.</emph>
     */
    @Test
    public void test_process_rejects_request_from_other_environment(@TempDir File dir) throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();
        assertThat(run("--generate-ta-certificate --env=test").exitCode).isZero();

        final File response = new File(dir.getAbsolutePath(), "response-initial.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        assertThat(
                run("--request=./src/test/resources/ta-request.xml" +
                        " --force-new-ta-certificate" +
                        " --response=" + response.getAbsolutePath() +
                        " --env=test").exitCode).isZero();

        final TAState taStateAfterFirstSigning = reloadTaState();

        assertThat(taStateAfterFirstSigning).isNotNull();

        // There is a single non-revoked manifest with one certificate on it.
        assertThat(taStateAfterFirstSigning.getSignedManifests())
                .filteredOn(Predicates.not(SignedObjectTracker::isRevoked))
                .map(SignedManifest::getManifest)
                .allMatch(manifest -> manifest.getFiles().keySet().stream().filter(s -> s.endsWith(".cer")).count() == 1)
                .hasSize(1);

        // Now sign a request from a different environment.
        // This MUST be rejected.

        assertThat(run("--request=./src/test/resources/ta-request-prepdev-env.xml" +
                        " --response=" + response.getAbsolutePath() +
                        " --env=test").exitCode
                ).isEqualTo(EXIT_ERROR_2);

        final TAState taStateAfterRejectedSigning = reloadTaState();
        // And TA state was not  modified by rejection
        assertThat(taStateAfterFirstSigning).isEqualTo(taStateAfterRejectedSigning);
    }


    @Test
    public void test_process_request_from_other_environment(@TempDir File dir) throws Exception {
        assertThat(run("--initialise --env=test").exitCode).isZero();
        assertThat(run("--generate-ta-certificate --env=test").exitCode).isZero();

        final File response = new File(dir.getAbsolutePath(), "response-initial.xml");

        final TAState taState0 = reloadTaState();
        final X509ResourceCertificate taCertBefore = getTaCertificate(taState0);

        assertThat(
                run("--request=./src/test/resources/ta-request.xml" +
                        " --force-new-ta-certificate" +
                        " --response=" + response.getAbsolutePath() +
                        " --env=test").exitCode).isZero();

        final TAState taStateAfterFirstSigning = reloadTaState();

        assertThat(taStateAfterFirstSigning).isNotNull();

        // There is a single non-revoked manifest with one certificate on it.
        assertThat(taStateAfterFirstSigning.getSignedManifests())
                .filteredOn(Predicates.not(SignedObjectTracker::isRevoked))
                .map(SignedManifest::getManifest)
                .allMatch(manifest -> manifest.getFiles().keySet().stream().filter(s -> s.endsWith(".cer")).count() == 1)
                .hasSize(1);

        // Now sign a request from a different environment, that will add the certificates from the other
        // environment on the manifest.

        assertThat(
                run("--request=./src/test/resources/ta-request-prepdev-env.xml" +
                        " --force-new-ta-certificate" +
                        " --response=" + response.getAbsolutePath() +
                        " --env=test").exitCode).isZero();

        final TAState taStateAfterRequestFromOtherEnvironment = reloadTaState();

        assertThat(taStateAfterRequestFromOtherEnvironment).isNotNull();

        // <emph>This is undesired in practice.</emph> But this checks that the default behaviour is to add
        // the second resource certificate
        assertThat(taStateAfterRequestFromOtherEnvironment.getSignedManifests())
                .filteredOn(Predicates.not(SignedObjectTracker::isRevoked))
                .map(SignedManifest::getManifest)
                .map(manifest -> manifest.getFiles().keySet().stream().filter(s -> s.endsWith(".cer")).count() == 2)
                .hasSize(1);

        // That is not revoked
        List<SignedResourceCertificate> signedProductionCertificatesAfterRequestFromOtherEnvironment = taStateAfterRequestFromOtherEnvironment.getSignedProductionCertificates();
        assertThat(signedProductionCertificatesAfterRequestFromOtherEnvironment)
                .allMatch(Predicates.not(SignedObjectTracker::isRevoked));

        // Now sign another, different, request, requesting revocation of the old objects.
        assertThat(
                run("--request=./src/test/resources/ta-request-prepdev-env-2.xml" +
                        " --force-new-ta-certificate" +
                        " --revoke-non-requested-objects" +
                        " --response=" + response.getAbsolutePath() +
                        " --env=test").exitCode).isZero();

        final TAState taStateAfterRevokeNonRequested = reloadTaState();

        assertThat(taStateAfterRevokeNonRequested).isNotNull();

        // State has just one certificate file on the single manifest
        assertThat(taStateAfterRevokeNonRequested.getSignedManifests())
                .filteredOn(Predicates.not(SignedObjectTracker::isRevoked))
                .map(SignedManifest::getManifest)
                .allMatch(manifest -> manifest.getFiles().keySet().stream().filter(s -> s.endsWith(".cer")).count() == 1)
                .hasSize(1);

        final X509Crl crlAfterRevoke = taStateAfterRevokeNonRequested.getCrl();

        // All previously present certificates are on the CRL
        assertThat(taStateAfterRequestFromOtherEnvironment.getSignedProductionCertificates())
                .map(SignedResourceCertificate::getResourceCertificate)
                .map(X509ResourceCertificate::getCertificate)
                .allMatch(crlAfterRevoke::isRevoked);

        List<SignedResourceCertificate> signedResourceCertificatesAfterRevokeNonRequested = taStateAfterRevokeNonRequested.getSignedProductionCertificates();

        // There is one additional certificate
        assertThat(signedResourceCertificatesAfterRevokeNonRequested)
                .hasSize(signedProductionCertificatesAfterRequestFromOtherEnvironment.size() + 1);
        // All **published** certificates are not revoked.
        assertThat(signedProductionCertificatesAfterRequestFromOtherEnvironment)
                .filteredOn(obj -> obj.isPublishable())
                .allMatch(Predicates.not(SignedObjectTracker::isRevoked));
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
        var state = TA.load(EnvStub.test()).getState();
        validateManifestAndCrlInvariants(state);
        return state;
    }
}
