package net.ripe.rpki.ta;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.ta.domain.request.SigningRequest;
import net.ripe.rpki.commons.ta.domain.request.TrustAnchorRequest;
import net.ripe.rpki.commons.ta.domain.response.SigningResponse;
import net.ripe.rpki.commons.ta.domain.response.TrustAnchorResponse;
import net.ripe.rpki.commons.ta.serializers.TrustAnchorRequestSerializer;
import net.ripe.rpki.commons.ta.serializers.TrustAnchorResponseSerializer;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.joda.time.Period;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.*;
import static org.assertj.core.api.Assertions.assertThat;

public class TATest {
    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "ERROR");
    }

    @Test
    public void initialise_ta() throws Exception {
        final TA ta = TA.initialise(Env.local());
        assertThat(Env.local()).isEqualTo(ta.getState().getConfig());
        assertThat(ta.getState().getEncoded()).isNotNull();
    }

    @Test
    public void serialize_ta() throws Exception {
        final String HOME = System.getProperty("user.home");

        final String xml = TA.initialise(Env.local()).serialize();
        assertThat(xml).contains("<taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>");
        assertThat(xml).contains("<taProductsPublicationUri>rsync://localhost:10873/repository/</taProductsPublicationUri>");
        assertThat(xml).contains("<keystoreProvider>SUN</keystoreProvider>");
        assertThat(xml).contains("<keypairGeneratorProvider>SunRsaSign</keypairGeneratorProvider>");
        assertThat(xml).contains("<signatureProvider>SunRsaSign</signatureProvider>");
        assertThat(xml).contains("<keystoreType>JKS</keystoreType>");
        // Constructed differently from implementation
        assertThat(xml).contains("<persistentStorageDir>" + HOME + "/export/bad/certification/ta/data</persistentStorageDir>");
        assertThat(xml).contains("<minimumValidityPeriod>P1M</minimumValidityPeriod>");
        assertThat(xml).contains("<keyStorePassphrase>");
        assertThat(xml).contains("</keyStorePassphrase>");
        assertThat(xml).contains("<keyStoreKeyAlias>");
        assertThat(xml).contains("</keyStoreKeyAlias>");
        assertThat(xml).startsWith("<TA>");
        assertThat(xml).endsWith("</TA>");
    }

    @Test
    public void deserialize_ta() throws Exception {
        final String HOME = System.getProperty("user.home");

        final String xml = "<TA>" +
              "<encoded>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</encoded>" +
              "<config>" +
                "<trustAnchorName>CN=RIPE-NCC-TA-TEST</trustAnchorName>" +
                "<keystoreProvider>SUN</keystoreProvider>" +
                "<keypairGeneratorProvider>SunRsaSign</keypairGeneratorProvider>" +
                "<signatureProvider>SunRsaSign</signatureProvider>" +
                "<keystoreType>JKS</keystoreType>" +
                "<persistentStorageDir>/export/certification/ta/data</persistentStorageDir>" +
                "<taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>" +
                "<taProductsPublicationUri>rsync://localhost:10873/repository/</taProductsPublicationUri>" +
                "<notificationUri>https://localhost:7788/notification.xml</notificationUri>" +
                "<minimumValidityPeriod>P6M</minimumValidityPeriod>" +
                "<updatePeriod>P3M</updatePeriod>" +
              "</config>" +
              "<keyStorePassphrase>2fe5a028-861a-47a0-a27f-7c657ea6ed49</keyStorePassphrase>" +
              "<keyStoreKeyAlias>RTA2</keyStoreKeyAlias>" +
              "<lastIssuedCertificateSerial>1</lastIssuedCertificateSerial>" +
              "<lastProcessedRequestTimestamp>0</lastProcessedRequestTimestamp>" +
              "<previousTaCertificates/>" +
              "<signedProductionCertificates/>" +
              "<signedManifests/>" +
            "</TA>";

        final TAState state = new TAStateSerializer().deserialize(xml);
        assertThat(state).isNotNull();
        assertThat(state.getConfig().getMinimumValidityPeriod()).isEqualTo(Period.months(6));
    }


    @Nested
    @DisplayName("Re-issue TA certificate")
    class ReIssueTest {
        @TempDir Path storageDir;

        TA ta;
        TrustAnchorRequest taRequest;
        TrustAnchorResponse taResponse;

        @BeforeEach
        void prepare() throws Exception {
            File request = new File(getClass().getResource("/ta-request.xml").getFile());
            File response = File.createTempFile("ta-0", "response.xml");
            response.deleteOnExit();

            ProgramOptions options = new ProgramOptions(
                    "--storage-directory", storageDir.toString(),
                    "--force-new-ta-certificate",
                    "--request", request.getCanonicalPath(),
                    "--response", response.getCanonicalPath()
            );

            ta = TA.initialise(Env.local());
            ta.processRequestXml(options);

            taRequest = new TrustAnchorRequestSerializer().deserialize(readFile(request));
            taResponse = new TrustAnchorResponseSerializer().deserialize(readFile(response));
        }

        @Test
        void published_object_uris() throws Exception {
            SigningRequest signingRequest = (SigningRequest) taRequest.getTaRequests().get(0);
            String subject = signingRequest.getResourceCertificateRequest().getSubjectDN().getName();
            String cn = subject.replaceFirst("^CN=", "");
            assertThat(taResponse.getPublishedObjects()).containsOnlyKeys(
                    new URI("rsync://rpki.ripe.net/ta/RIPE-NCC-TA-TEST.cer"),
                    new URI("rsync://rpki.ripe.net/repository/RIPE-NCC-TA-TEST.crl"),
                    new URI("rsync://rpki.ripe.net/repository/RIPE-NCC-TA-TEST.mft"),
                    new URI("rsync://rpki.ripe.net/repository/" + cn + ".cer")
            );
        }

        @Test
        void crl_location() throws Exception {
            URI taCrl = new URI("rsync://rpki.ripe.net/repository/RIPE-NCC-TA-TEST.crl");
            SigningResponse signingResponse = (SigningResponse) taResponse.getTaResponses().get(0);
            assertThat(signingResponse.getCertificate().getCrlDistributionPoints()).isEqualTo(new URI[] { taCrl });

            CertificateRepositoryObject manifest = taResponse.getPublishedObjects().get(
                    new URI("rsync://rpki.ripe.net/repository/RIPE-NCC-TA-TEST.mft")
            );
            assertThat(manifest.getCrlUri()).isEqualTo(taCrl);
        }

        @Test
        void sia_descriptor_uris() throws Exception {
            X509CertificateInformationAccessDescriptor[] siaDescriptors = ta.getTaCertificate().getSubjectInformationAccess();
            assertThat(siaLocationFor(ID_AD_CA_REPOSITORY, siaDescriptors)).hasValue("rsync://rpki.ripe.net/repository/");
            assertThat(siaLocationFor(ID_AD_RPKI_NOTIFY, siaDescriptors)).hasValue("https://rrdp.ripe.net/notification.xml");
            assertThat(siaLocationFor(ID_AD_RPKI_MANIFEST, siaDescriptors)).hasValue("rsync://rpki.ripe.net/repository/RIPE-NCC-TA-TEST.mft");
        }
    }

    private Optional<String> siaLocationFor(ASN1ObjectIdentifier identifier, X509CertificateInformationAccessDescriptor[] descriptors) {
        for (X509CertificateInformationAccessDescriptor descriptor : descriptors) {
            if (identifier.equals(descriptor.getMethod())) {
                return Optional.of(descriptor.getLocation().toString());
            }
        }
        return Optional.empty();
    }

    private String readFile(File f) throws IOException {
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }
}
