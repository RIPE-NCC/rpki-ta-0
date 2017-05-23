package net.ripe.rpki.ta;

import com.google.common.base.Preconditions;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.ta.config.Config;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;

public class TA {

    private static final int TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS = 5;

    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("AS0-AS65536, 0/0, 0::/0");

    private final Config config;
    private BigInteger serial = BigInteger.ONE;

    public TA(Config config) {
        this.config = config;
    }

    public X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(
            X509CertificateInformationAccessDescriptor... siaDescriptors) {

        final Map<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor> descriptorsMap = new HashMap<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor>();
        for (final X509CertificateInformationAccessDescriptor descriptor : siaDescriptors) {
            descriptorsMap.put(descriptor.getMethod(), descriptor);
        }

        final X509CertificateInformationAccessDescriptor productsPublication =
                Preconditions.checkNotNull(descriptorsMap.get(ID_AD_CA_REPOSITORY), "SIA descriptors must include 'CA Repository'");

        final URI manifestUri = TaNames.manifestPublicationUri(productsPublication.getLocation(), config.trustAnchorName);

        descriptorsMap.put(ID_AD_RPKI_MANIFEST,
                new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_MANIFEST, manifestUri));

        return descriptorsMap.values().toArray(new X509CertificateInformationAccessDescriptor[descriptorsMap.size()]);
    }

    private X509ResourceCertificate issueRootCertificate() {
        final X509ResourceCertificateBuilder taBuilder = new X509ResourceCertificateBuilder();
        taBuilder.withCa(true);
        taBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);

        taBuilder.withIssuerDN(config.trustAnchorName);
        taBuilder.withSubjectDN(config.trustAnchorName);
        taBuilder.withSerial(serial);
        taBuilder.withResources(ROOT_RESOURCE_SET);

        // TODO Implement
//        taBuilder.withPublicKey(rootKeyPair.getPublic());
//        taBuilder.withSigningKeyPair(rootKeyPair);
        taBuilder.withSignatureProvider(config.signatureProvider);
        taBuilder.withSubjectKeyIdentifier(true);
        taBuilder.withAuthorityKeyIdentifier(false);

        final DateTime now = new DateTime(DateTimeZone.UTC);
        taBuilder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS)));

        // TODO Implement
//        taBuilder.withSubjectInformationAccess(siaDescriptors);

        return taBuilder.build();
    }

}
