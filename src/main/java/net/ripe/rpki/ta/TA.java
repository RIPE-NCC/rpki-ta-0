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
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.persistence.TAPersistence;
import net.ripe.rpki.ta.serializers.LegacyTASerializer;
import net.ripe.rpki.ta.serializers.TAState;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;

public class TA {

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

    public TAState initialiseTaState(boolean generateRootCertificate) throws Exception {
        return createTaState(generateRootKeyPair(), generateRootCertificate);
    }

    public TAState initialiseTaState() throws Exception {
        return createTaState(generateRootKeyPair(), true);
    }

    private TAState migrateTaState(final LegacyTA legacyTA) throws Exception {
        final byte[] encodedLegacy = legacyTA.getTrustAnchorKeyStore().getEncoded();
        final KeyPair newRootKeyPair = KeyStore.legacy(config).decode(encodedLegacy).getLeft();
        return createTaState(newRootKeyPair, true);
    }

    TAState migrateTaState(final String oldTaFilePath) throws Exception {
        final String legacyXml = new TAPersistence(config).load(oldTaFilePath);
        final LegacyTA legacyTA = new LegacyTASerializer().deserialize(legacyXml);
        return migrateTaState(legacyTA);
    }

    private TAState createTaState(KeyPair newRootKeyPair, boolean generateRootCertificate) throws Exception {
        final byte[] encoded;
        if (generateRootCertificate) {
            final X509CertificateInformationAccessDescriptor[] descriptors = generateSiaDescriptors(config.getTaProductsPublicationUri());
            encoded = KeyStore.of(config).encode(newRootKeyPair, issueRootCertificate(newRootKeyPair, descriptors));
        } else {
            encoded = KeyStore.of(config).encode(newRootKeyPair);
        }

        final TAState taState = new TAState();
        /* TODO Add more stuff here:

         Old TrustAnchor class contains:
            private transient KeyPair caKeyPair;

            private URI taCertificatePublicationUri;
            private URI taProductsPublicationUri;

            private X500Principal caName;
            private X509Crl crl;
            private BigInteger lastCrlNumber;

            private String signatureProvider;
            private transient KeyPairFactory keyPairFactory;

            private TrustAnchorKeyStore trustAnchorKeyStore;
            private transient X509ResourceCertificate currentTaCertificate;
            private List<SignedResourceCertificate> previousTaCertificates = new ArrayList<SignedResourceCertificate>();
            private List<SignedResourceCertificate> signedProductionCertificates = new ArrayList<SignedResourceCertificate>();

            private List<SignedManifest> signedManifests = new ArrayList<SignedManifest>();
            private ManifestCms manifest;

            private BigInteger lastManifestNumber = BigInteger.ZERO;

            private BigInteger lastIssuedCertificateSerial;
            private Long lastProcessedRequestTimestamp = 0L;
          */
        taState.setConfig(config);
        taState.setEncoded(encoded);
        return taState;
    }

    static String serialize(final TAState taState) {
        return new TAStateSerializer().serialize(taState);
    }

    public void persist(TAState taState) throws IOException {
        new TAPersistence(config).save(serialize(taState));
    }

    public TAState load() throws Exception {
        final String xml = new TAPersistence(config).load();
        return new TAStateSerializer().deserialize(xml);
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

    private X509ResourceCertificate issueRootCertificate(final KeyPair rootKeyPair, final X509CertificateInformationAccessDescriptor[] descriptors) {
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

        taBuilder.withSubjectInformationAccess(descriptors);

        return taBuilder.build();
    }

    private X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(URI taProductsPublicationUri) {
        return generateSiaDescriptors(
                new X509CertificateInformationAccessDescriptor(ID_AD_CA_REPOSITORY, taProductsPublicationUri));
    }

    private KeyPair generateRootKeyPair() {
        return keyPairFactory.withProvider(config.getKeypairGeneratorProvider()).generate();
    }

    TAState createNewTAState(final ProgramOptions programOptions) throws Exception {
        if (programOptions.hasInitialise()) {
            return initialiseTaState(programOptions.hasGenerateTACertificate());
        }

        if (programOptions.hasInitialiseFromOld()) {
            return migrateTaState(programOptions.getOldTaFilePath());
        }

        // there is no '--initialise' but there is '--generate-ta-certificate'
        if (programOptions.hasGenerateTACertificate()) {
            // try to read and decode existing state
            final TAState taState = load();
            final Pair<KeyPair, X509ResourceCertificate> decoded = KeyStore.of(config).decode(taState.getEncoded());

            // re-issue the certificate


            return initialiseTaState();
        }

        throw new Exception("The program options are inconsistent: " + programOptions.getUsageString());
    }

    public Config getConfig() {
        return config;
    }

}
