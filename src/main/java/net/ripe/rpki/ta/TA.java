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

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.io.Files;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsBuilder;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.EncodedPublicKey;
import net.ripe.rpki.commons.crypto.util.KeyPairFactory;
import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import net.ripe.rpki.commons.crypto.x509cert.*;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.domain.TAStateBuilder;
import net.ripe.rpki.ta.domain.request.ResourceCertificateRequestData;
import net.ripe.rpki.ta.domain.request.RevocationRequest;
import net.ripe.rpki.ta.domain.request.SigningRequest;
import net.ripe.rpki.ta.domain.request.TaRequest;
import net.ripe.rpki.ta.domain.request.TrustAnchorRequest;
import net.ripe.rpki.ta.domain.response.ErrorResponse;
import net.ripe.rpki.ta.domain.response.RevocationResponse;
import net.ripe.rpki.ta.domain.response.SigningResponse;
import net.ripe.rpki.ta.domain.response.TaResponse;
import net.ripe.rpki.ta.domain.response.TrustAnchorResponse;
import net.ripe.rpki.ta.persistence.TAPersistence;
import net.ripe.rpki.ta.processing.RequestProcessorException;
import net.ripe.rpki.ta.serializers.LegacyTASerializer;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import net.ripe.rpki.ta.serializers.TrustAnchorRequestSerializer;
import net.ripe.rpki.ta.serializers.TrustAnchorResponseSerializer;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedObjectTracker;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY;

public class TA {

    private final static Logger LOGGER = LoggerFactory.getLogger(TA.class);

    private static final int TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS = 100;

    private static final IpResourceSet ALL_RESOURCES_SET = IpResourceSet.parse("AS0-AS4294967295, 0/0, 0::/0");

    private final Config config;
    private final transient KeyPairFactory keyPairFactory;

    public TA(Config config) {
        this.config = config;
        this.keyPairFactory = new KeyPairFactory(config.getKeypairGeneratorProvider());
    }

    public TAState initialiseTaState() throws Exception {
        return createTaState(new TAStateBuilder(config), generateRootKeyPair(), BigInteger.ONE);
    }

    TAState migrateTaState(final String oldTaFilePath) throws Exception {
        final String legacyXml = new TAPersistence(config).load(oldTaFilePath);
        final LegacyTA legacyTA = new LegacyTASerializer().deserialize(legacyXml);
        return migrateTaState(legacyTA);
    }

    private TAState migrateTaState(final LegacyTA legacyTA) throws Exception {
        final byte[] encodedLegacy = legacyTA.getTrustAnchorKeyStore().getEncoded();
        final KeyPair oldKeyPair = KeyStore.legacy(config).decode(encodedLegacy).getLeft();

        TAStateBuilder taStateBuilder = new TAStateBuilder(config);

        taStateBuilder.withCrl(legacyTA.getCrl());

        // the last issued crl and/or manifest number are identical so we pick the crl one:
        taStateBuilder.withLastCrlSerial(legacyTA.getLastCrlNumber());
        taStateBuilder.withLastMftSerial(legacyTA.getLastManifestNumber());

        return createTaState(taStateBuilder, oldKeyPair, next(legacyTA.lastIssuedCertificateSerial));
    }

    private TAState createTaState(final TAStateBuilder taStateBuilder, KeyPair keyPair, final BigInteger serial) throws Exception {
        final X509CertificateInformationAccessDescriptor[] descriptors = generateSiaDescriptors(config.getTaProductsPublicationUri());
        final KeyStore keyStore = KeyStore.of(config);
        final byte[] encoded = keyStore.encode(keyPair, issueRootCertificate(keyPair, descriptors, serial));

        return createTaState(taStateBuilder, encoded, keyStore, serial);
    }

    private TAState createTaState(final TAStateBuilder taStateBuilder, byte[] encoded, KeyStore keyStore, final BigInteger serial) throws Exception {
        return taStateBuilder.
                withEncoded(encoded).
                withKeyStoreKeyAlias(keyStore.getKeyStoreKeyAlias()).
                withKeyStorePassphrase(keyStore.getKeyStorePassPhrase()).
                withLastIssuedCertificateSerial(serial).
                build();
    }

    private static BigInteger next(final BigInteger serial) {
        return serial == null ? BigInteger.ONE : serial.add(BigInteger.ONE);
    }

    static String serialize(final TAState taState) {
        return new TAStateSerializer().serialize(taState);
    }

    public void persist(TAState taState) throws IOException {
        new TAPersistence(config).save(serialize(taState));
    }

    public TAState loadTAState() throws Exception {
        final String xml = new TAPersistence(config).load();
        return new TAStateSerializer().deserialize(xml);
    }

    byte[] getCertificateDER() throws Exception {
        return KeyStore.of(config).decode(loadTAState().getEncoded()).getRight().getEncoded();
    }

    String getCurrentTrustAnchorLocator() throws Exception {
        X509ResourceCertificate certificate = KeyStore.of(config).decode(loadTAState().getEncoded()).getRight();
        return String.valueOf(config.getTaCertificatePublicationUri())
                + TaNames.certificateFileName(certificate.getSubject()) + "\n"
                + X509CertificateUtil.getEncodedSubjectPublicKeyInfo(certificate.getCertificate());
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

        descriptorsMap.put(ID_AD_RPKI_MANIFEST, aiaDescriptor(ID_AD_RPKI_MANIFEST, manifestUri));
        descriptorsMap.put(ID_AD_RPKI_NOTIFY, aiaDescriptor(ID_AD_RPKI_NOTIFY, getConfig().getNotificationUri()));

        return descriptorsMap.values().toArray(new X509CertificateInformationAccessDescriptor[descriptorsMap.size()]);
    }

    private X509ResourceCertificate issueRootCertificate(final KeyPair rootKeyPair,
                                                         final X509CertificateInformationAccessDescriptor[] descriptors,
                                                         final BigInteger serial) {
        final X509ResourceCertificateBuilder taBuilder = new X509ResourceCertificateBuilder();

        taBuilder.withCa(true);
        taBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        taBuilder.withIssuerDN(config.getTrustAnchorName());
        taBuilder.withSubjectDN(config.getTrustAnchorName());
        taBuilder.withSerial(serial);
        taBuilder.withResources(ALL_RESOURCES_SET);
        taBuilder.withPublicKey(rootKeyPair.getPublic());
        taBuilder.withSigningKeyPair(rootKeyPair);
        taBuilder.withSignatureProvider(getSignatureProvider());
        taBuilder.withSubjectKeyIdentifier(true);
        taBuilder.withAuthorityKeyIdentifier(false);

        final DateTime now = new DateTime(DateTimeZone.UTC);
        taBuilder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS)));

        taBuilder.withSubjectInformationAccess(descriptors);

        return taBuilder.build();
    }

    private X509ResourceCertificate reIssueRootCertificate(final KeyPair rootKeyPair,
                                                           final X509CertificateInformationAccessDescriptor[] extraSiaDescriptors,
                                                           final X509ResourceCertificate currentTaCertificate,
                                                           final BigInteger serial) {
        final X509ResourceCertificateBuilder taBuilder = new X509ResourceCertificateBuilder();

        taBuilder.withCa(true);
        taBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        taBuilder.withIssuerDN(config.getTrustAnchorName());
        taBuilder.withSubjectDN(config.getTrustAnchorName());
        taBuilder.withSerial(serial);
        taBuilder.withResources(ALL_RESOURCES_SET);
        taBuilder.withPublicKey(rootKeyPair.getPublic());
        taBuilder.withSigningKeyPair(rootKeyPair);
        taBuilder.withSignatureProvider(getSignatureProvider());
        taBuilder.withSubjectKeyIdentifier(true);
        taBuilder.withAuthorityKeyIdentifier(false);

        final DateTime now = new DateTime(DateTimeZone.UTC);
        taBuilder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS)));

        // TODO Normally extraSiaDescriptors come from the request
        taBuilder.withSubjectInformationAccess(merge(currentTaCertificate.getSubjectInformationAccess(), extraSiaDescriptors));

        return taBuilder.build();
    }

    private X509CertificateInformationAccessDescriptor[] merge(
            X509CertificateInformationAccessDescriptor[] subjectInformationAccess,
            X509CertificateInformationAccessDescriptor[] extraSiaDescriptors) {
        if (extraSiaDescriptors == null) {
            return subjectInformationAccess;
        }

        final HashMap<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor> result = new HashMap<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor>();

        for (final X509CertificateInformationAccessDescriptor descriptor : subjectInformationAccess) {
            result.put(descriptor.getMethod(), descriptor);
        }
        for (final X509CertificateInformationAccessDescriptor descriptor : extraSiaDescriptors) {
            result.put(descriptor.getMethod(), descriptor);
        }
        return result.values().toArray(new X509CertificateInformationAccessDescriptor[result.size()]);
    }

    private X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(URI taProductsPublicationUri) {
        return generateSiaDescriptors(aiaDescriptor(ID_AD_CA_REPOSITORY, taProductsPublicationUri));
    }

    private KeyPair generateRootKeyPair() {
        return keyPairFactory.withProvider(config.getKeypairGeneratorProvider()).generate();
    }

    private boolean hasState() {
        return new TAPersistence(config).taStateExists();
    }

    TAState createNewTAState(final ProgramOptions programOptions) throws Exception {
        if (programOptions.hasInitialiseOption()) {
            if (hasState()) {
                throw new Exception("TA state is already serialised to " + config.getPersistentStorageDir() + ".");
            }
            return initialiseTaState();
        }

        if (programOptions.hasInitialiseFromOldOption()) {
            if (hasState()) {
                throw new Exception("TA state is already serialised to " + config.getPersistentStorageDir() + ".");
            }
            return migrateTaState(programOptions.getOldTaFilePath());
        }

        // there is no '--initialise' but there is '--generate-ta-certificate'
        if (programOptions.hasGenerateTACertificateOption()) {
            if (!hasState()) {
                throw new Exception("No TA state found, please initialise it first.");
            }
            // try to read and decode existing state
            final KeyStore keyStore = KeyStore.of(config);
            final TAState taState = loadTAState();
            final Pair<KeyPair, X509ResourceCertificate> decoded = keyStore.decode(taState.getEncoded());

            // re-issue the TA certificate
            final KeyPair keyPair = decoded.getLeft();
            final X509ResourceCertificate taCertificate = decoded.getRight();
            final BigInteger nextSerial = nextIssuedCertSerial(taState);
            final X509ResourceCertificate newTACertificate = reIssueRootCertificate(keyPair,
                    generateSiaDescriptors(config.getTaProductsPublicationUri()), taCertificate, nextSerial);

            final TAStateBuilder taStateBuilder = new TAStateBuilder(config);
            taStateBuilder.withCrl(taState.getCrl());

            return createTaState(taStateBuilder, keyStore.encode(keyPair, newTACertificate), keyStore, nextSerial);
        }

        throw new BadOptions("The program options are inconsistent.");
    }

    void processRequestXml(ProgramOptions options) throws Exception {
        final String requestXml = Files.toString(new File(options.getRequestFile()), Charsets.UTF_8);
        final TrustAnchorRequest request = new TrustAnchorRequestSerializer().deserialize(requestXml);
        final Pair<TrustAnchorResponse, TAState> p = processRequest(request);
        final String response = new TrustAnchorResponseSerializer().serialize(p.getLeft());
        final File responseFile = new File(options.getResponseFile());
        Files.write(response, responseFile, Charsets.UTF_8);
        try {
            persist(p.getRight());
        } catch (Exception e) {
            if (responseFile.exists()) {
                responseFile.delete();
            }
            throw e;
        }
    }

    private Pair<TrustAnchorResponse, TAState> processRequest(final TrustAnchorRequest request) throws Exception {
        final TAState taState = loadTAState();
        validateRequestSerial(request, taState);

        final Pair<KeyPair, X509ResourceCertificate> decoded = KeyStore.of(config).decode(taState.getEncoded());
        final TAState newTAState = copyTAState(taState);

        final SignCtx signCtx = new SignCtx(request, newTAState, new DateTime(), decoded.getRight(), decoded.getLeft());

        // TODO Ask Tim why do we do it
        updateUrls(request, signCtx);

        final List<TaResponse> taResponses = Lists.newArrayList();
        for (final TaRequest r : request.getTaRequests()) {
            if (r instanceof SigningRequest) {
                taResponses.add(processSignRequest((SigningRequest) r, signCtx));
            } else if (r instanceof RevocationRequest) {
                taResponses.add(processRevocationRequest((RevocationRequest) r, signCtx));
            }
        }

        return Pair.of(new TrustAnchorResponse(request.getCreationTimestamp(), getObjectsToBePublished(signCtx), taResponses), newTAState);
    }

    /**
     * A weird way to make a deep copy of TA state.
     * There should be a better one, but Java sucks
     */
    private static TAState copyTAState(final TAState ts) {
        final TAStateSerializer serializer = new TAStateSerializer();
        return serializer.deserialize(serializer.serialize(ts));
    }


    private void validateRequestSerial(TrustAnchorRequest request, final TAState taState) {
        final DateTime requestTime = new DateTime(request.getCreationTimestamp());
        final DateTime lastRequestTime = new DateTime(taState.getLastProcessedRequestTimestamp());

        if (requestTime.isBefore(lastRequestTime)) {
            throw new RequestProcessorException("Request, dated: " + requestTime + ", is BEFORE last processed request, dated: " + lastRequestTime);
        }
        if (requestTime.equals(lastRequestTime)) {
            throw new RequestProcessorException("Request has EXACT millisecond date as previously processed request. Response should already exist! Cowardly bailing out..");
        }
    }

    private void updateUrls(final TrustAnchorRequest taRequest, final SignCtx signCtx) {
        signCtx.taState.getConfig().setTaCertificatePublicationUri(taRequest.getTaCertificatePublicationUri());
        for (final X509CertificateInformationAccessDescriptor descriptor : taRequest.getSiaDescriptors()) {
            if (ID_AD_CA_REPOSITORY.equals(descriptor.getMethod())) {
                signCtx.taState.getConfig().setTaProductsPublicationUri(descriptor.getLocation());
            }
        }
    }

    private TaResponse processSignRequest(final SigningRequest signingRequest, final SignCtx signCtx) {
        final ResourceCertificateRequestData requestData = signingRequest.getResourceCertificateRequest();

        final X509ResourceCertificate allResourcesCertificate = signProductionCertificate(requestData, signCtx);
        revokeAllCertificatesForKey(signCtx);

        signCtx.taState.getSignedProductionCertificates().add(new SignedResourceCertificate(
                TaNames.certificateFileName(allResourcesCertificate.getSubject()), allResourcesCertificate));

        final URI publicationPoint = TaNames.certificatePublicationUri(getConfig().getTaCertificatePublicationUri(), allResourcesCertificate.getSubject());

        return new SigningResponse(signingRequest.getRequestId(), requestData.getResourceClassName(), publicationPoint, allResourcesCertificate);
    }

    private TaResponse processRevocationRequest(final RevocationRequest revocationRequest, final SignCtx signCtx) {
        boolean revoked = revokeAllCertificatesForKey(signCtx);
        if (revoked) {
            return new RevocationResponse(revocationRequest.getRequestId(), revocationRequest.getResourceClassName(), revocationRequest.getEncodedPublicKey());
        } else {
            return new ErrorResponse(revocationRequest.getRequestId(), "No certificate to revoke for this encoded public key");
        }
    }

    private Map<URI, CertificateRepositoryObject> getObjectsToBePublished(final SignCtx signCtx) {
        for (final SignedManifest signedManifest : signCtx.taState.getSignedManifests()) {
            signedManifest.revoke();
        }
        final URI taProductsPublicationUri = config.getTaProductsPublicationUri();
        final URI taCertificatePublicationUri = config.getTaCertificatePublicationUri();

        final Map<URI, CertificateRepositoryObject> result = new HashMap<URI, CertificateRepositoryObject>();
        result.put(taCertificatePublicationUri.resolve(TaNames.certificateFileName(signCtx.certificate.getSubject())), signCtx.certificate);
        final X509Crl newCrl = createNewCrl(signCtx);
        signCtx.taState.setCrl(newCrl);
        result.put(taProductsPublicationUri.resolve(TaNames.crlFileName(signCtx.certificate.getSubject())), newCrl);
        result.put(taProductsPublicationUri.resolve(TaNames.manifestFileName(signCtx.certificate.getSubject())), createNewManifest(signCtx));
        for (final SignedResourceCertificate cert : signCtx.taState.getSignedProductionCertificates()) {
            if (cert.isPublishable()) {
                result.put(taProductsPublicationUri.resolve(cert.getFileName()), cert.getCertificateRepositoryObject());
            }
        }
        return result;
    }

    private X509Crl createNewCrl(final SignCtx signCtx) {
        return createNewCrl(signCtx.keyPair, signCtx.taState, signCtx.certificate.getSubject(), signCtx.now);
    }

    private X509Crl createNewCrl(final KeyPair keyPair, final TAState taState, final X500Principal issuer, final  DateTime now) {
        final X509CrlBuilder builder = new X509CrlBuilder()
                .withAuthorityKeyIdentifier(keyPair.getPublic())
                .withNumber(nextCrlNumber(taState))
                .withIssuerDN(issuer)
                .withThisUpdateTime(now)
                .withNextUpdateTime(calculateNextUpdateTime(now))
                .withSignatureProvider(getSignatureProvider());
        fillRevokedObjects(builder, taState.getSignedProductionCertificates());
        fillRevokedObjects(builder, taState.getPreviousTaCertificates());
        fillRevokedObjects(builder, taState.getSignedManifests());
        return builder.build(keyPair.getPrivate());
    }

    private void fillRevokedObjects(X509CrlBuilder builder, List<? extends SignedObjectTracker> revokedObjects) {
        for (final SignedObjectTracker signedObject : revokedObjects) {
            if (signedObject.shouldAppearInCrl()) {
                builder.addEntry(signedObject.getCertificateSerial(), signedObject.getRevocationTime());
            }
        }
    }

    private ManifestCms createNewManifest(final SignCtx signCtx) {
        final DateTime nextUpdateTime = calculateNextUpdateTime(signCtx.now);

        final KeyPair eeKeyPair = keyPairFactory.withProvider(getKeypairGeneratorProvider()).generate();
        final X509ResourceCertificate eeCertificate = createEeCertificateForManifest(eeKeyPair, nextUpdateTime, signCtx);

        final ManifestCmsBuilder manifestBuilder = createBasicManifestBuilder(nextUpdateTime, eeCertificate, signCtx);
        manifestBuilder.addFile(TaNames.crlFileName(signCtx.certificate.getSubject()), signCtx.taState.getCrl().getEncoded());
        for (final SignedResourceCertificate signedProductionCertificate : signCtx.taState.getSignedProductionCertificates()) {
            if (signedProductionCertificate.isPublishable()) {
                X509ResourceCertificate resourceCertificate = signedProductionCertificate.getResourceCertificate();
                manifestBuilder.addFile(TaNames.certificateFileName(resourceCertificate.getSubject()), resourceCertificate.getEncoded());
            }
        }
        final ManifestCms manifest = manifestBuilder.build(eeKeyPair.getPrivate());
        signCtx.taState.getSignedManifests().add(new SignedManifest(manifest));
        return manifest;
    }

    private X509ResourceCertificate signProductionCertificate(final ResourceCertificateRequestData request,
                                                              final SignCtx signCtx) {
        final X500Principal issuer = signCtx.certificate.getSubject();

        final URI taCertificatePublicationUri = getConfig().getTaCertificatePublicationUri();
        final URI taProductsPublicationUri = getTaProductsPublicationUri();
        final X509CertificateInformationAccessDescriptor[] taAIA = { aiaDescriptor(
                X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS,
                URI.create(taCertificatePublicationUri.toString() + TaNames.certificateFileName(issuer)))
        };

        final X509CertificateInformationAccessDescriptor aia = aiaDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS,
                TaNames.certificatePublicationUri(taCertificatePublicationUri, issuer));

        final X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(true);
        builder.withIssuerDN(issuer);
        builder.withSubjectDN(request.getSubjectDN());
        builder.withSerial(nextIssuedCertSerial(signCtx.taState));
        builder.withPublicKey(new EncodedPublicKey(request.getEncodedSubjectPublicKey()));
        builder.withSigningKeyPair(signCtx.keyPair);
        builder.withValidityPeriod(new ValidityPeriod(signCtx.now, signCtx.now.plus(getConfig().getMinimumValidityPeriod())));
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withSubjectKeyIdentifier(true);
        builder.withAuthorityKeyIdentifier(true);
        builder.withAuthorityInformationAccess(aia);
        builder.withCrlDistributionPoints(TaNames.crlPublicationUri(taProductsPublicationUri, issuer));
        builder.withResources(ALL_RESOURCES_SET);
        builder.withSubjectInformationAccess(request.getSubjectInformationAccess());
        builder.withCrlDistributionPoints(TaNames.clrPublicationUriForParentCertificate(signCtx.certificate));
        builder.withSignatureProvider(getSignatureProvider());
        builder.withAuthorityInformationAccess(taAIA);
        return builder.build();
    }

    private X509ResourceCertificate createEeCertificateForManifest(KeyPair eeKeyPair, DateTime nextUpdateTime, final SignCtx signCtx) {
        ValidityPeriod validityPeriod = new ValidityPeriod(signCtx.now, nextUpdateTime);
        X500Principal eeSubject = new X500Principal("CN=" + KeyPairUtil.getAsciiHexEncodedPublicKeyHash(eeKeyPair.getPublic()));

        RpkiSignedObjectEeCertificateBuilder builder = new RpkiSignedObjectEeCertificateBuilder();

        final X500Principal caName = signCtx.certificate.getSubject();
        final URI taCertificatePublicationUri = getConfig().getTaCertificatePublicationUri();
        builder.withIssuerDN(caName);
        builder.withSubjectDN(eeSubject);
        builder.withSerial(nextIssuedCertSerial(signCtx.taState));
        builder.withPublicKey(eeKeyPair.getPublic());
        builder.withSigningKeyPair(signCtx.keyPair);
        builder.withValidityPeriod(validityPeriod);
        builder.withParentResourceCertificatePublicationUri(TaNames.certificatePublicationUri(taCertificatePublicationUri, caName));
        builder.withCrlUri(TaNames.crlPublicationUri(getTaProductsPublicationUri(), caName));
        builder.withCorrespondingCmsPublicationPoint(TaNames.manifestPublicationUri(getTaProductsPublicationUri(), caName));
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withSignatureProvider(getSignatureProvider());
        return builder.build();
    }

    private ManifestCmsBuilder createBasicManifestBuilder(DateTime nextUpdateTime, X509ResourceCertificate eeCertificate, final SignCtx signCtx) {
        return new ManifestCmsBuilder().
                withCertificate(eeCertificate).
                withThisUpdateTime(signCtx.now).
                withNextUpdateTime(nextUpdateTime).
                withManifestNumber(nextManifestNumber(signCtx.taState)).
                withSignatureProvider(getSignatureProvider());
    }

    private BigInteger nextCrlNumber(final TAState taState) {
        final BigInteger next = next(taState.getLastCrlSerial());
        taState.setLastCrlSerial(next);
        return next;
    }

    private BigInteger nextManifestNumber(final TAState taState) {
        final BigInteger next = next(taState.getLastMftSerial());
        taState.setLastMftSerial(next);
        return next;
    }

    private BigInteger nextIssuedCertSerial(TAState taState) {
        final BigInteger next = next(taState.getLastIssuedCertificateSerial());
        taState.setLastIssuedCertificateSerial(next);
        return next;
    }

    private boolean revokeAllCertificatesForKey(final SignCtx signCtx) {
        return revokeAllCertificatesForKey(KeyPairUtil.getEncodedKeyIdentifier(signCtx.keyPair.getPublic()), signCtx.taState);
    }

    private boolean revokeAllCertificatesForKey(String encodedPublicKey, final TAState taState) {
        boolean result = false;
        for (final SignedResourceCertificate certificate : taState.getSignedProductionCertificates()) {
            final PublicKey publicKey = certificate.getResourceCertificate().getPublicKey();
            if (encodedPublicKey.equals(KeyPairUtil.getEncodedKeyIdentifier(publicKey)) && !certificate.isRevoked()) {
                certificate.revoke();
                result = true;
            }
        }
        return result;
    }

    private DateTime calculateNextUpdateTime(final DateTime now) {
        final DateTime minimum = now.plus(getConfig().getMinimumValidityPeriod());
        DateTime result = now;
        while (result.isBefore(minimum)) {
            result = result.plus(getConfig().getUpdatePeriod());
        }
        return result;
    }

    private String getSignatureProvider() {
        return getConfig().getSignatureProvider();
    }

    private String getKeypairGeneratorProvider() {
        return getConfig().getKeypairGeneratorProvider();
    }

    private URI getTaProductsPublicationUri() {
        return getConfig().getTaProductsPublicationUri();
    }

    public Config getConfig() {
        return config;
    }

    private X509CertificateInformationAccessDescriptor aiaDescriptor(ASN1ObjectIdentifier method, URI location) {
        return new X509CertificateInformationAccessDescriptor(method, location);
    }

    /**
     * Just an utility class to carry the environment around when doing the signing.
     */
    private class SignCtx {
        final TrustAnchorRequest request;
        final TAState taState;
        final DateTime now;
        final X509ResourceCertificate certificate;
        final KeyPair keyPair;

        private SignCtx(TrustAnchorRequest request, TAState taState, DateTime now, X509ResourceCertificate certificate, KeyPair keyPair) {
            this.request = request;
            this.taState = taState;
            this.now = now;
            this.certificate = certificate;
            this.keyPair = keyPair;
        }
    }

}
