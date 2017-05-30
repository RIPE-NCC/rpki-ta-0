package net.ripe.rpki.ta;

/*-
 * ========================LICENSE_START=================================
 * RIPE NCC Trust Anchor
 * -
 * Copyright (C) 2017 RIPE NCC
 * -
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the RIPE NCC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * =========================LICENSE_END==================================
 */

import com.google.common.base.Preconditions;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactory;
import net.ripe.rpki.commons.crypto.util.KeyStoreException;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.serializers.TAState;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;

public class TA implements Serializable {

    private static final int TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS = 5;

    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("AS0-AS65536, 0/0, 0::/0");

    private final Config config;
    private final transient KeyPairFactory keyPairFactory;

    // TODO We should also support other values taken from the serialized TA
    private BigInteger serial = BigInteger.ONE;

    public TA(Config config) {
        this.config = config;
        this.keyPairFactory = new KeyPairFactory(config.getKeypairGeneratorProvider());
    }

    public TAState initialiseTaState() throws Exception {
        final KeyPair rootKeyPair = generateRootKeyPair();
        final X509ResourceCertificate rootTaCertificate = issueRootCertificate(rootKeyPair);

        byte[] encoded = new KeyStore(config).encode(rootKeyPair, rootTaCertificate);

        final TAState taState = new TAState();
        taState.setConfig(config);
        taState.setEncoded(encoded);
        return taState;
    }


    private X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(
            X509CertificateInformationAccessDescriptor... siaDescriptors) {

        final Map<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor> descriptorsMap = new HashMap<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor>();
        for (final X509CertificateInformationAccessDescriptor descriptor : siaDescriptors) {
            descriptorsMap.put(descriptor.getMethod(), descriptor);
        }

        final X509CertificateInformationAccessDescriptor productsPublication =
                Preconditions.checkNotNull(descriptorsMap.get(ID_AD_CA_REPOSITORY), "SIA descriptors must include 'CA Repository'");

        final URI manifestUri = TaNames.manifestPublicationUri(productsPublication.getLocation(), config.getTrustAnchorName());

        descriptorsMap.put(ID_AD_RPKI_MANIFEST,
                new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_MANIFEST, manifestUri));

        return descriptorsMap.values().toArray(new X509CertificateInformationAccessDescriptor[descriptorsMap.size()]);
    }

    private X509ResourceCertificate issueRootCertificate(final KeyPair rootKeyPair) {
        final X509ResourceCertificateBuilder taBuilder = new X509ResourceCertificateBuilder();

        taBuilder.withCa(true);
        taBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        taBuilder.withIssuerDN(config.getTrustAnchorName());
        taBuilder.withSubjectDN(config.getTrustAnchorName());
        taBuilder.withSerial(serial);
        taBuilder.withResources(ROOT_RESOURCE_SET);
        taBuilder.withPublicKey(rootKeyPair.getPublic());
        taBuilder.withSigningKeyPair(rootKeyPair);
        taBuilder.withSignatureProvider(config.getSignatureProvider());
        taBuilder.withSubjectKeyIdentifier(true);
        taBuilder.withAuthorityKeyIdentifier(false);

        final DateTime now = new DateTime(DateTimeZone.UTC);
        taBuilder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS)));

        taBuilder.withSubjectInformationAccess(generateSiaDescriptors(config.getTaProductsPublicationUri()));

        return taBuilder.build();
    }

    private X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(URI taProductsPublicationUri) {
        return generateSiaDescriptors(
                new X509CertificateInformationAccessDescriptor(ID_AD_CA_REPOSITORY, taProductsPublicationUri));
    }

    private KeyPair generateRootKeyPair() {
        return keyPairFactory.withProvider(config.getKeypairGeneratorProvider()).generate();
    }

    public static String serialize(TAState taState) {
        final TAStateSerializer serializer = new TAStateSerializer();
        return serializer.serialize(taState);
    }

}
