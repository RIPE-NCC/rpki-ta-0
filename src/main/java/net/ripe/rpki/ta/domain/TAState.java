package net.ripe.rpki.ta.domain;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


/**
 * TA state to be serialized to ta.xml
 */
// package protected constructor so XStream can instantiate this object
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Data
public class TAState {

    private byte[] encoded;
    private Config config;
    private X509Crl crl;

    private String keyStorePassphrase;
    private String keyStoreKeyAlias;

    private BigInteger lastIssuedCertificateSerial;

    private BigInteger lastCrlSerial;
    private BigInteger lastMftSerial;

    private Long lastProcessedRequestTimestamp = 0L;

    private List<SignedResourceCertificate> previousTaCertificates = new ArrayList<SignedResourceCertificate>();

    private List<SignedResourceCertificate> signedProductionCertificates = new ArrayList<SignedResourceCertificate>();

    private List<SignedManifest> signedManifests = new ArrayList<SignedManifest>();
}
