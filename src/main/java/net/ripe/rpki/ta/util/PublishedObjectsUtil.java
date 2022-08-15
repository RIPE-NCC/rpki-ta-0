package net.ripe.rpki.ta.util;

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;

import javax.annotation.CheckForNull;
import java.net.URI;
import java.util.Map;

@UtilityClass
@Slf4j(topic="PublishedObjects")
public class PublishedObjectsUtil {
    public static final String LINE_SEPARATOR = Strings.repeat("=", 40);

    /**
     * Log the subject information access attributes of the certificates.
     */
    private static void logSubjectInformationAccess(X509ResourceCertificate cert) {
        final X509CertificateInformationAccessDescriptor[] sias = cert.getSubjectInformationAccess();
        if (sias == null) {
            log.error("  sia: No SubjectInformationAccess present on certificate(subject={}, serial={})", cert.getSubject(), cert.getSerialNumber());
        } else {
            for (int i = 0; i < sias.length; i++) {
                log.info("  sia[{}]: {} ({})", i, sias[i].getLocation(), sias[i].getMethod());
            }
        }
    }

    private static String bytesFormat(@CheckForNull byte[] bytes) {
        return bytes != null ? BaseEncoding.base16().encode(bytes) : "[null]";
    }

    public static void logObject(CertificateRepositoryObject object) {
        if (object instanceof X509Crl) {
            final X509Crl x509Crl = (X509Crl) object;
            log.info("  CRL number={} thisUpdate={} nextUpdate={} aki={}", x509Crl.getNumber(), x509Crl.getThisUpdateTime(), x509Crl.getNextUpdateTime(), bytesFormat(x509Crl.getAuthorityKeyIdentifier()));
            x509Crl.getRevokedCertificates().forEach(crlEntry -> {
                log.info("  {} {}", Strings.padEnd(crlEntry.getSerialNumber().toString(), 60, ' '), crlEntry.getRevocationDateTime());
            });
        } else if (object instanceof ManifestCms) {
            final ManifestCms manifestCms = (ManifestCms) object;
            final X509ResourceCertificate eeCert = manifestCms.getCertificate();
            log.info("  Manifest number={} nextUpdate={} signingTime={} contentType={}", manifestCms.getNumber(), manifestCms.getNextUpdateTime(), manifestCms.getSigningTime(), manifestCms.getContentType());
            log.info("  Entries:");
            manifestCms.getFiles().forEach((fileName, hashBytes) -> {
                log.info("    {} {}", Strings.padEnd(fileName, 60, ' '), BaseEncoding.base16().encode(hashBytes));
            });
            log.info("  EE certificate subject={} serial={} notBefore={} notAfter={} parent={} resources={}", eeCert.getSubject(), eeCert.getSerialNumber(), eeCert.getValidityPeriod().getNotValidBefore(), eeCert.getValidityPeriod().getNotValidAfter(), eeCert.getParentCertificateUri(), eeCert.getResources());
            logSubjectInformationAccess(eeCert);
        } else if (object instanceof RpkiSignedObject) {
            final RpkiSignedObject signedObject = (RpkiSignedObject)object;
            final X509ResourceCertificate eeCert = signedObject.getCertificate();
            log.info("  signed object signingTime={} contentType={}", signedObject.getSigningTime(), signedObject.getContentType());
            log.info("  EE certificate subject={} serial={} notBefore={} notAfter={} parent={} resources={}", eeCert.getSubject(), eeCert.getSerialNumber(), eeCert.getValidityPeriod().getNotValidBefore(), eeCert.getValidityPeriod().getNotValidAfter(), eeCert.getParentCertificateUri(), eeCert.getResources());
            logSubjectInformationAccess(eeCert);
        } else if (object instanceof X509ResourceCertificate) {
            final X509ResourceCertificate cert = (X509ResourceCertificate)object;
            log.info("  certificate subject={} serial={} notBefore={} notAfter={} parent={} resources={} ski={} aki={}", cert.getSubject(), cert.getSerialNumber(), cert.getValidityPeriod().getNotValidBefore(), cert.getValidityPeriod().getNotValidAfter(), cert.getParentCertificateUri(), cert.getResources(), bytesFormat(cert.getSubjectKeyIdentifier()), bytesFormat(cert.getAuthorityKeyIdentifier()));
            logSubjectInformationAccess(cert);
        } else {
            log.info("  (no further details for this type)");
        }
    }

    private static void logObjectEntry(Map.Entry<URI, CertificateRepositoryObject> entry) {
        log.info(LINE_SEPARATOR);
        log.info("location: {}", entry.getKey());
        log.info(LINE_SEPARATOR);

        logObject(entry.getValue());
    }

    /**
     * Log what objects are in the map as well as the individual files.
     * @param objects objects to log
     */
    public static void logPublishedObjects(Map<URI, CertificateRepositoryObject> objects) {
        log.info(LINE_SEPARATOR);
        log.info("Currently published files:");
        log.info(LINE_SEPARATOR);
        objects.entrySet().forEach((entry) -> log.info("{}:", entry.getKey()));
        // logObject adds header.
        objects.entrySet().forEach(PublishedObjectsUtil::logObjectEntry);
        log.info(LINE_SEPARATOR);
    }
}
