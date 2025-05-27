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
import java.util.Base64;
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

        // Do no store big base64 blob in the code, generate it every time
        var encodedState = TA.initialise(Env.local()).getState().getEncoded();
        var encoded = Base64.getEncoder().encodeToString(encodedState);

        final String xml = "<TA>" +
              "<encoded>" + encoded + "</encoded>" +
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
        return Files.readString(f.toPath());
    }
}
