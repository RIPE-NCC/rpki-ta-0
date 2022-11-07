package net.ripe.rpki.ta;

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.*;
import static org.assertj.core.api.Assertions.assertThat;

public class TATest {
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
        assertThat(xml).contains("<updatePeriod>P3M</updatePeriod>");
        assertThat(xml).contains("<keyStorePassphrase>");
        assertThat(xml).contains("</keyStorePassphrase>");
        assertThat(xml).contains("<keyStoreKeyAlias>");
        assertThat(xml).contains("</keyStoreKeyAlias>");
        assertThat(xml).startsWith("<TA>");
        assertThat(xml).endsWith("</TA>");
    }

    @Test
    public void resignTaCertificate() throws Exception {
        TA ta = TA.initialise(Env.local());
        String request = getClass().getResource("/ta-request.xml").getFile();
        ProgramOptions options = new ProgramOptions(
                "--force-new-ta-certificate",
                "--request", request,
                "--response", "-"
        );
        ta.processRequestXml(options);

        X509CertificateInformationAccessDescriptor[] siaDescriptors = ta.getTaCertificate().getSubjectInformationAccess();
        assertThat(siaLocationFor(ID_AD_CA_REPOSITORY, siaDescriptors)).hasValue("rsync://rpki.ripe.net/repository/");
        assertThat(siaLocationFor(ID_AD_RPKI_NOTIFY, siaDescriptors)).hasValue("https://rrdp.ripe.net/notification.xml");
        assertThat(siaLocationFor(ID_AD_RPKI_MANIFEST, siaDescriptors)).hasValue("rsync://rpki.ripe.net/ta/RIPE-NCC-TA-TEST.mft");
    }

    private Optional<String> siaLocationFor(ASN1ObjectIdentifier identifier, X509CertificateInformationAccessDescriptor[] descriptors) {
        for (X509CertificateInformationAccessDescriptor descriptor : descriptors) {
            if (identifier.equals(descriptor.getMethod())) {
                return Optional.of(descriptor.getLocation().toString());
            }
        }
        return Optional.empty();
    }
 }
