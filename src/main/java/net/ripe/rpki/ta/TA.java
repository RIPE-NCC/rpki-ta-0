package net.ripe.rpki.ta;


import com.google.common.base.Preconditions;
import com.google.common.base.Verify;
import com.google.common.io.CharStreams;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
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
import net.ripe.rpki.commons.ta.domain.request.*;
import net.ripe.rpki.commons.ta.domain.response.*;
import net.ripe.rpki.commons.ta.serializers.TrustAnchorRequestSerializer;
import net.ripe.rpki.commons.ta.serializers.TrustAnchorResponseSerializer;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.domain.TAStateBuilder;
import net.ripe.rpki.ta.exception.OperationAbortedException;
import net.ripe.rpki.ta.exception.RequestProcessorException;
import net.ripe.rpki.ta.persistence.TAPersistence;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedObjectTracker;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;
import net.ripe.rpki.ta.util.PublishedObjectsUtil;
import net.ripe.rpki.ta.util.ValidityPeriods;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.*;

@Slf4j(topic = "TA")
public class TA {

    public static final IpResourceSet ALL_RESOURCES_SET = IpResourceSet.parse("AS0-AS4294967295, 0/0, 0::/0");

    @Getter
    private TAState state;

    private final ValidityPeriods validityPeriods;

    public static TA initialise(Config config) throws GeneralSecurityException, IOException {
        final KeyPairFactory keyPairFactory = new KeyPairFactory(config.getKeystoreProvider());
        final KeyPair rootKeyPair = keyPairFactory.withProvider(config.getKeypairGeneratorProvider()).generate();
        final TAState state = createTaState(config, rootKeyPair);
        return new TA(state);
    }

    public static TA load(Config config) throws IOException {
        final String xml = new TAPersistence(config).load();
        final TAState state = new TAStateSerializer().deserialize(xml);
        return new TA(state);
    }

    private TA(TAState state) {
        this.state = state;
        this.validityPeriods = new ValidityPeriods(state.getConfig());
    }

    private static TAState createTaState(Config config, KeyPair keyPair) throws GeneralSecurityException, IOException {
        final TAStateBuilder taStateBuilder = new TAStateBuilder(config);
        final X509CertificateInformationAccessDescriptor[] descriptors = generateSiaDescriptors(config);
        final KeyStore keyStore = KeyStore.of(config);
        final X509ResourceCertificate rootCert = issueRootCertificate(config.getTrustAnchorName(),
                    keyPair, descriptors, BigInteger.ONE, config.getSignatureProvider());
        final byte[] encoded = keyStore.encode(keyPair, rootCert);

        return createTaState(taStateBuilder, encoded, keyStore, BigInteger.ONE);
    }

    private static TAState createTaState(final TAStateBuilder taStateBuilder, byte[] encoded, KeyStore keyStore, final BigInteger serial) {
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

    public String serialize() {
        return new TAStateSerializer().serialize(state);
    }

    public void persist() throws IOException {
        new TAPersistence(state.getConfig()).save(serialize());
    }

    byte[] getCertificateDER() throws Exception {
        return getTaCertificate().getEncoded();
    }

    public X509ResourceCertificate getTaCertificate() throws Exception {
        return KeyStore.of(state.getConfig()).decode(state.getEncoded()).getRight();
    }

    String getCurrentTrustAnchorLocator() throws Exception {
        X509ResourceCertificate certificate = getTaCertificate();
        return state.getConfig().getTaCertificatePublicationUri()
                + TaNames.certificateFileName(certificate.getSubject()) + "\n\n"
                + X509CertificateUtil.getEncodedSubjectPublicKeyInfo(certificate.getCertificate()) + "\n";
    }

    private static X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(
            final X500Principal trustAnchorName,
            final URI notificationUri,
            final X509CertificateInformationAccessDescriptor... siaDescriptors
    ) {
        final Map<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor> descriptorsMap = new HashMap<>();
        for (final X509CertificateInformationAccessDescriptor descriptor : siaDescriptors) {
            descriptorsMap.put(descriptor.getMethod(), descriptor);
        }

        final X509CertificateInformationAccessDescriptor productsPublication =
                Preconditions.checkNotNull(descriptorsMap.get(ID_AD_CA_REPOSITORY), "SIA descriptors must include 'CA Repository'");

        final URI manifestUri = TaNames.manifestPublicationUri(productsPublication.getLocation(), trustAnchorName);

        descriptorsMap.put(ID_AD_RPKI_MANIFEST, new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_MANIFEST, manifestUri));
        descriptorsMap.put(ID_AD_RPKI_NOTIFY, new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_NOTIFY, notificationUri));

        return descriptorsMap.values().toArray(new X509CertificateInformationAccessDescriptor[0]);
    }

    private static X509ResourceCertificate issueRootCertificate(
            final X500Principal trustAnchorName,
            final KeyPair rootKeyPair,
            final X509CertificateInformationAccessDescriptor[] descriptors,
            final BigInteger serial,
            final String signatureProvider
    ) {
        final X509ResourceCertificateBuilder taBuilder = new X509ResourceCertificateBuilder();

        taBuilder.withCa(true);
        taBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        taBuilder.withIssuerDN(trustAnchorName);
        taBuilder.withSubjectDN(trustAnchorName);
        taBuilder.withSerial(serial);
        taBuilder.withResources(ALL_RESOURCES_SET);
        taBuilder.withValidityPeriod(ValidityPeriods.taCertificate());
        taBuilder.withPublicKey(rootKeyPair.getPublic());
        taBuilder.withSigningKeyPair(rootKeyPair);
        taBuilder.withSignatureProvider(signatureProvider);
        taBuilder.withAuthorityKeyIdentifier(false);
        taBuilder.withSubjectInformationAccess(descriptors);

        return taBuilder.build();
    }

    private X509ResourceCertificate reIssueRootCertificate(final KeyPair rootKeyPair,
                                                           final X509CertificateInformationAccessDescriptor[] extraSiaDescriptors,
                                                           final X509ResourceCertificate currentTaCertificate,
                                                           final BigInteger serial) {
        final X509ResourceCertificateBuilder taCertificateBuilder = new X509ResourceCertificateBuilder();

        taCertificateBuilder.withCa(true);
        taCertificateBuilder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        taCertificateBuilder.withIssuerDN(state.getConfig().getTrustAnchorName());
        taCertificateBuilder.withSubjectDN(state.getConfig().getTrustAnchorName());
        taCertificateBuilder.withSerial(serial);
        taCertificateBuilder.withResources(ALL_RESOURCES_SET);
        taCertificateBuilder.withValidityPeriod(ValidityPeriods.taCertificate());
        taCertificateBuilder.withPublicKey(rootKeyPair.getPublic());
        taCertificateBuilder.withSigningKeyPair(rootKeyPair);
        taCertificateBuilder.withSignatureProvider(getSignatureProvider());
        taCertificateBuilder.withAuthorityKeyIdentifier(false);
        taCertificateBuilder.withSubjectInformationAccess(merge(currentTaCertificate.getSubjectInformationAccess(), extraSiaDescriptors));

        return taCertificateBuilder.build();
    }

    private X509CertificateInformationAccessDescriptor[] merge(
            X509CertificateInformationAccessDescriptor[] subjectInformationAccess,
            X509CertificateInformationAccessDescriptor[] extraSiaDescriptors) {
        if (extraSiaDescriptors == null) {
            return subjectInformationAccess;
        }

        final Map<ASN1ObjectIdentifier, X509CertificateInformationAccessDescriptor> result = new HashMap<>();

        for (final X509CertificateInformationAccessDescriptor descriptor : subjectInformationAccess) {
            result.put(descriptor.getMethod(), descriptor);
        }
        for (final X509CertificateInformationAccessDescriptor descriptor : extraSiaDescriptors) {
            result.put(descriptor.getMethod(), descriptor);
        }
        return result.values().toArray(new X509CertificateInformationAccessDescriptor[0]);
    }

    private static X509CertificateInformationAccessDescriptor[] generateSiaDescriptors(Config config) {
        return generateSiaDescriptors(
                config.getTrustAnchorName(),
                config.getNotificationUri(),
                new X509CertificateInformationAccessDescriptor(ID_AD_CA_REPOSITORY, config.getTaProductsPublicationUri())
        );
    }

    public static boolean hasState(Config config) {
        return new TAPersistence(config).taStateExists();
    }

    public void generateTACertificate() throws GeneralSecurityException, IOException {
        // try to read and decode existing state
        final KeyStore keyStore = KeyStore.of(state.getConfig());
        final Pair<KeyPair, X509ResourceCertificate> decoded = keyStore.decode(state.getEncoded());

        // re-issue the TA certificate
        final KeyPair keyPair = decoded.getLeft();
        final X509ResourceCertificate taCertificate = decoded.getRight();
        final BigInteger nextSerial = nextIssuedCertSerial(state);
        final X509ResourceCertificate newTACertificate = reIssueRootCertificate(
                keyPair,
                generateSiaDescriptors(state.getConfig()),
                taCertificate,
                nextSerial
        );

        final TAStateBuilder taStateBuilder = new TAStateBuilder(state.getConfig());
        taStateBuilder.withCrl(state.getCrl());

        this.state = createTaState(taStateBuilder, keyStore.encode(keyPair, newTACertificate), keyStore, nextSerial);
    }

    void processRequestXml(ProgramOptions options) throws Exception {
        try (InputStream in = requestXml(options.getRequestFile());
             PrintStream out = responseXml(options.getResponseFile())) {
            final String requestXml = CharStreams.toString(new InputStreamReader(in, StandardCharsets.UTF_8));
            final TrustAnchorRequest request = new TrustAnchorRequestSerializer().deserialize(requestXml);
            final Pair<TrustAnchorResponse, TAState> p = processRequest(request, options);
            final String response = new TrustAnchorResponseSerializer().serialize(p.getLeft());
            this.state = p.getRight();
            out.print(response);
        }
    }

    private InputStream requestXml(String file) throws IOException {
        log.info("reading request XML from {}", file);
        if ("-".equals(file)) {
            return System.in;
        } else {
            return new FileInputStream(file);
        }
    }

    private PrintStream responseXml(String file) throws IOException {
        log.info("writing response XML to {}", file);
        if ("-".equals(file)) {
            return System.out;
        } else {
            return new PrintStream(new FileOutputStream(file));
        }
    }

    private Pair<TrustAnchorResponse, TAState> processRequest(final TrustAnchorRequest request, ProgramOptions options) throws Exception {
        validateRequestSerial(request, state);

        final KeyStore keyStore = KeyStore.of(state.getConfig());
        final Pair<KeyPair, X509ResourceCertificate> decoded = keyStore.decode(state.getEncoded());
        TAState newTAState = copyTAState(state);

        SignCtx signCtx = new SignCtx(request, newTAState, decoded.getRight(), decoded.getLeft());

        // First process revocation requests, before processing the "revoke all issued resource certificates" command
        // line option. Otherwise error responses are generated due to requesting a revocation for an already revoked
        // certificate.
        final List<TaResponse> taResponses = new ArrayList<>();
        for (final TaRequest r : request.getTaRequests()) {
            if (r instanceof RevocationRequest) {
                taResponses.add(processRevocationRequest((RevocationRequest) r, signCtx));
            }
        }

        // If requested, revoke all the currently issued resource certificates that are present in the state.
        if (options.hasRevokeAllIssuedResourceCertificates()) {
            revokeAllIssuedResourceCertificates(newTAState);
        }

        // re-issue TA certificate if some of the publication points are changed
        final Optional<String> whyReissue = taCertificateHasToBeReIssued(request, signCtx.taState.getConfig());
        if (whyReissue.isPresent()) {
            if (!options.hasForceNewTaCertificate()) {
                throw new OperationAbortedException("TA certificate has to be re-issued: " + whyReissue.get() +
                    ", bailing out. Provide " + ProgramOptions.FORCE_NEW_TA_CERT_OPT + " option to force TA certificate re-issue.");
            }

            // copy new SIAs to the TA config
            updateTaConfigUrls(request, signCtx);

            final KeyPair keyPair = decoded.getLeft();
            final X509ResourceCertificate taCertificate = decoded.getRight();
            final BigInteger nextSerial = nextIssuedCertSerial(state);

            X509CertificateInformationAccessDescriptor[] ta0SiaDescriptors = generateSiaDescriptors(
                    signCtx.taState.getConfig()
            );
            final X509ResourceCertificate newTACertificate = reIssueRootCertificate(keyPair,
                merge(ta0SiaDescriptors, request.getSiaDescriptors()), taCertificate, nextSerial);

            TAStateBuilder taStateBuilder = new TAStateBuilder(newTAState);
            taStateBuilder.withCrl(newTAState.getCrl());
            newTAState = createTaState(taStateBuilder, keyStore.encode(keyPair, newTACertificate), keyStore, nextSerial);
            signCtx = new SignCtx(request, newTAState, newTACertificate, keyPair);
        }

        // Process sign requests _after_ revoking all issued certificates (command line option), to avoid immediately
        // revoking the certificates that we just issued...
        for (final TaRequest r : request.getTaRequests()) {
            if (r instanceof SigningRequest) {
                taResponses.add(processSignRequest((SigningRequest) r, signCtx));
            }
        }

        Map<URI, CertificateRepositoryObject> publishedObjects = updateObjectsToBePublished(signCtx);
        PublishedObjectsUtil.logPublishedObjects(publishedObjects);

        return Pair.of(new TrustAnchorResponse(request.getCreationTimestamp(), publishedObjects, taResponses), newTAState);
    }

    private Optional<String> taCertificateHasToBeReIssued(TrustAnchorRequest taRequest, Config taConfig) {
        if (!taConfig.getTaCertificatePublicationUri().equals(taRequest.getTaCertificatePublicationUri())) {
            return Optional.of("Different TA certificate location, request has '" +
                    taRequest.getTaCertificatePublicationUri() + "', config has '" + taConfig.getTaCertificatePublicationUri() + "'");
        }
        for (final X509CertificateInformationAccessDescriptor descriptor : taRequest.getSiaDescriptors()) {
            if (ID_AD_CA_REPOSITORY.equals(descriptor.getMethod()) && !descriptor.getLocation().equals(taConfig.getTaProductsPublicationUri())) {
                return Optional.of("Different TA products URL, request has '" +
                    descriptor.getLocation() + "', config has '" + taConfig.getNotificationUri() + "'");
            } else if (ID_AD_RPKI_NOTIFY.equals(descriptor.getMethod()) && !descriptor.getLocation().equals(taConfig.getNotificationUri())) {
                return Optional.of("Different notification.xml URL, request has '" +
                    descriptor.getLocation() + "', config has '" + taConfig.getNotificationUri() + "'");
            }
        }
        return Optional.empty();
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
        final DateTime requestTime = new DateTime(request.getCreationTimestamp(), DateTimeZone.UTC);
        final DateTime lastRequestTime = new DateTime(taState.getLastProcessedRequestTimestamp(), DateTimeZone.UTC);

        if (requestTime.isBefore(lastRequestTime)) {
            throw new RequestProcessorException("Request, dated: " + requestTime + ", is BEFORE last processed request, dated: " + lastRequestTime);
        }
        if (requestTime.equals(lastRequestTime)) {
            throw new RequestProcessorException("Request has EXACT millisecond date as previously processed request. Response should already exist! Cowardly bailing out..");
        }
    }

    private void updateTaConfigUrls(final TrustAnchorRequest taRequest, final SignCtx signCtx) {
        signCtx.taState.getConfig().setTaCertificatePublicationUri(taRequest.getTaCertificatePublicationUri());
        for (final X509CertificateInformationAccessDescriptor descriptor : taRequest.getSiaDescriptors()) {
            if (ID_AD_CA_REPOSITORY.equals(descriptor.getMethod())) {
                signCtx.taState.getConfig().setTaProductsPublicationUri(descriptor.getLocation());
            } else if (ID_AD_RPKI_NOTIFY.equals(descriptor.getMethod())) {
                signCtx.taState.getConfig().setNotificationUri(descriptor.getLocation());
            }
        }
    }

    private TaResponse processSignRequest(final SigningRequest signingRequest, final SignCtx signCtx) {
        final ResourceCertificateRequestData requestData = signingRequest.getResourceCertificateRequest();

        final X509ResourceCertificate allResourcesCertificate = signAllResourcesCertificate(requestData, signCtx);
        revokeAllCertificatesForKey(KeyPairUtil.getEncodedKeyIdentifier(allResourcesCertificate.getPublicKey()), signCtx.taState);

        signCtx.taState.getSignedProductionCertificates().add(new SignedResourceCertificate(
                TaNames.certificateFileName(allResourcesCertificate.getSubject()), allResourcesCertificate));

        final URI publicationPoint = TaNames.certificatePublicationUri(
            signCtx.taState.getConfig().getTaProductsPublicationUri(), allResourcesCertificate.getSubject());

        return new SigningResponse(signingRequest.getRequestId(), requestData.getResourceClassName(), publicationPoint, allResourcesCertificate);
    }

    private TaResponse processRevocationRequest(final RevocationRequest revocationRequest, final SignCtx signCtx) {
        boolean revoked = revokeAllCertificatesForKey(revocationRequest.getEncodedPublicKey(),  signCtx.taState);
        if (revoked) {
            return new RevocationResponse(revocationRequest.getRequestId(), revocationRequest.getResourceClassName(), revocationRequest.getEncodedPublicKey());
        } else {
            return new ErrorResponse(revocationRequest.getRequestId(), "No certificate to revoke for this encoded public key");
        }
    }

    private Map<URI, CertificateRepositoryObject> updateObjectsToBePublished(final SignCtx signCtx) {
        final Config config = signCtx.taState.getConfig();
        // Revoke currently issued manifests
        for (final SignedManifest signedManifest : signCtx.taState.getSignedManifests()) {
            signedManifest.revoke();
        }
        final URI taProductsPublicationUri = config.getTaProductsPublicationUri();
        final URI taCertificatePublicationUri = config.getTaCertificatePublicationUri();

        final Map<URI, CertificateRepositoryObject> result = new HashMap<>();
        result.put(taCertificatePublicationUri.resolve(TaNames.certificateFileName(signCtx.taCertificate.getSubject())), signCtx.taCertificate);
        final X509Crl newCrl = createNewCrl(signCtx);
        signCtx.taState.setCrl(newCrl);
        result.put(taProductsPublicationUri.resolve(TaNames.crlFileName(signCtx.taCertificate.getSubject())), newCrl);
        result.put(taProductsPublicationUri.resolve(TaNames.manifestFileName(signCtx.taCertificate.getSubject())), createNewManifest(signCtx));

        int expectedSize = 3;

        for (final SignedResourceCertificate cert : signCtx.taState.getSignedProductionCertificates()) {
            if (cert.isPublishable()) {
                result.put(taProductsPublicationUri.resolve(cert.getFileName()), cert.getCertificateRepositoryObject());
                expectedSize++;
            }
        }

        // Track the objects and verify that they do not have overlapping names.
        Verify.verify(expectedSize == result.size());
        return Collections.unmodifiableMap(result);
    }

    private X509Crl createNewCrl(final SignCtx signCtx) {
        final X500Principal issuer = signCtx.taCertificate.getSubject();
        final ValidityPeriod validityPeriod = validityPeriods.crl();
        final X509CrlBuilder builder = new X509CrlBuilder()
                .withAuthorityKeyIdentifier(signCtx.keyPair.getPublic())
                .withNumber(nextCrlNumber(signCtx.taState))
                .withIssuerDN(issuer)
                .withThisUpdateTime(validityPeriod.getNotValidBefore())
                .withNextUpdateTime(validityPeriod.getNotValidAfter())
                .withSignatureProvider(getSignatureProvider());
        fillRevokedObjects(builder, signCtx.taState.getSignedProductionCertificates());
        fillRevokedObjects(builder, signCtx.taState.getPreviousTaCertificates());
        fillRevokedObjects(builder, signCtx.taState.getSignedManifests());
        return builder.build(signCtx.keyPair.getPrivate());
    }

    private void fillRevokedObjects(X509CrlBuilder builder, List<? extends SignedObjectTracker> revokedObjects) {
        for (final SignedObjectTracker signedObject : revokedObjects) {
            if (signedObject.shouldAppearInCrl()) {
                builder.addEntry(signedObject.getCertificateSerial(), signedObject.getRevocationTime());
            }
        }
    }

    private ManifestCms createNewManifest(final SignCtx signCtx) {
        // Generate a new key pair for the one-time-use EE certificate and do not store it, this prevents accidental
        // re-use in the future, and prevents keys from piling up in the HSM 'security world'
        final KeyPairFactory keyPairFactory = new KeyPairFactory(state.getConfig().getKeystoreProvider());
        final KeyPair eeKeyPair = keyPairFactory.withProvider("SunRsaSign").generate();
        final X509ResourceCertificate eeCertificate = createEeCertificateForManifest(eeKeyPair, signCtx);

        final ManifestCmsBuilder manifestBuilder = createBasicManifestBuilder(eeCertificate, signCtx);
        manifestBuilder.addFile(TaNames.crlFileName(signCtx.taCertificate.getSubject()), signCtx.taState.getCrl().getEncoded());
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

    private X509ResourceCertificate signAllResourcesCertificate(final ResourceCertificateRequestData request,
                                                                final SignCtx signCtx) {
        final Config config = signCtx.taState.getConfig();
        final X500Principal issuer = signCtx.taCertificate.getSubject();

        final URI taCertificatePublicationUri = config.getTaCertificatePublicationUri();
        final URI taProductsPublicationUri = config.getTaProductsPublicationUri();
        final X509CertificateInformationAccessDescriptor[] taAIA = {
                new X509CertificateInformationAccessDescriptor(
                        X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS,
                        URI.create(taCertificatePublicationUri.toString() + TaNames.certificateFileName(issuer))
                )
        };

        final X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(true);
        builder.withIssuerDN(issuer);
        builder.withSubjectDN(request.getSubjectDN());
        builder.withSerial(nextIssuedCertSerial(signCtx.taState));
        builder.withPublicKey(new EncodedPublicKey(request.getEncodedSubjectPublicKey()));
        builder.withSigningKeyPair(signCtx.keyPair);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withCrlDistributionPoints(TaNames.crlPublicationUri(taProductsPublicationUri, issuer));
        builder.withResources(ALL_RESOURCES_SET);
        builder.withValidityPeriod(validityPeriods.allResourcesCertificate());
        builder.withSubjectInformationAccess(request.getSubjectInformationAccess());
        builder.withSignatureProvider(getSignatureProvider());
        builder.withAuthorityInformationAccess(taAIA);
        return builder.build();
    }

    private X509ResourceCertificate createEeCertificateForManifest(KeyPair eeKeyPair, final SignCtx signCtx) {
        X500Principal eeSubject = new X500Principal("CN=" + KeyPairUtil.getAsciiHexEncodedPublicKeyHash(eeKeyPair.getPublic()));

        RpkiSignedObjectEeCertificateBuilder builder = new RpkiSignedObjectEeCertificateBuilder();

        final X500Principal caName = signCtx.taCertificate.getSubject();
        final URI taCertificatePublicationUri = signCtx.taState.getConfig().getTaCertificatePublicationUri();
        builder.withIssuerDN(caName);
        builder.withSubjectDN(eeSubject);
        builder.withSerial(nextIssuedCertSerial(signCtx.taState));
        builder.withPublicKey(eeKeyPair.getPublic());
        builder.withSigningKeyPair(signCtx.keyPair);
        builder.withValidityPeriod(validityPeriods.eeCert());
        builder.withParentResourceCertificatePublicationUri(TaNames.certificatePublicationUri(taCertificatePublicationUri, caName));
        builder.withCrlUri(TaNames.crlPublicationUri(signCtx.taState.getConfig().getTaProductsPublicationUri(), caName));
        builder.withCorrespondingCmsPublicationPoint(TaNames.manifestPublicationUri(signCtx.taState.getConfig().getTaProductsPublicationUri(), caName));
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withSignatureProvider(getSignatureProvider());
        return builder.build();
    }

    private ManifestCmsBuilder createBasicManifestBuilder(X509ResourceCertificate eeCertificate, final SignCtx signCtx) {
        ValidityPeriod validityPeriod = validityPeriods.manifest();
        return new ManifestCmsBuilder().
                withCertificate(eeCertificate)
                .withThisUpdateTime(validityPeriod.getNotValidBefore())
                .withNextUpdateTime(validityPeriod.getNotValidAfter())
                .withManifestNumber(nextManifestNumber(signCtx.taState))
                .withSignatureProvider(getSignatureProvider());
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

    /**
     * Revoke all certificates signed by the TA.
     * Needed when you intend to replace all signed objects by just those in the request.
     * @return true if anything was revoked.
     */
    private void revokeAllIssuedResourceCertificates(final TAState taState) {
        taState.getSignedProductionCertificates().forEach(SignedResourceCertificate::revoke);
    }

    private String getSignatureProvider() {
        return state.getConfig().getSignatureProvider();
    }

    /**
     * Just an utility class to carry the environment around when doing the signing.
     */
    private static class SignCtx {
        final TrustAnchorRequest request;
        final TAState taState;
        final X509ResourceCertificate taCertificate;
        final KeyPair keyPair;

        private SignCtx(TrustAnchorRequest request, TAState taState, X509ResourceCertificate taCertificate, KeyPair keyPair) {
            this.request = request;
            this.taState = taState;
            this.taCertificate = taCertificate;
            this.keyPair = keyPair;
        }
    }

}
