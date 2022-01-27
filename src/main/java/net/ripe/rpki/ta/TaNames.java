package net.ripe.rpki.ta;


import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.apache.commons.lang3.StringUtils;

import javax.security.auth.x500.X500Principal;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;

public final class TaNames {

    private TaNames() {
    }

    public static String certificateFileName(X500Principal certificateName) {
        return encodePath(stripCNEqualsFromPrincipal(certificateName) + ".cer");
    }

    public static URI certificatePublicationUri(URI publicationUri, X500Principal certificateName) {
        return objectPublicationUri(publicationUri, certificateFileName(certificateName));
    }

    public static String crlFileName(X500Principal taCertificateName) {
        return encodePath(stripCNEqualsFromPrincipal(taCertificateName) + ".crl");
    }

    public static URI crlPublicationUri(URI publicationUri, X500Principal taCertificateName) {
        return objectPublicationUri(publicationUri, crlFileName(taCertificateName));
    }

    public static URI clrPublicationUriForParentCertificate(X509ResourceCertificate currentTaCertificate) {
        return crlPublicationUri(currentTaCertificate.getRepositoryUri(), currentTaCertificate.getIssuer());
    }

    public static String manifestFileName(X500Principal taCertificateName) {
        return encodePath(stripCNEqualsFromPrincipal(taCertificateName) + ".mft");
    }

    public static URI manifestPublicationUri(URI publicationUri, X500Principal taCertificateName) {
        return objectPublicationUri(publicationUri, manifestFileName(taCertificateName));
    }

    public static URI objectPublicationUri(URI publicationUri, String fileName) {
        return publicationUri.resolve(fileName);
    }

    private static String encodePath(String path) {
        try {
            return URLEncoder.encode(path, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException("Can't encode path:" + path, e);
        }
    }

    private static String stripCNEqualsFromPrincipal(X500Principal certificateName) {
        return StringUtils.substring(certificateName.getName(), "CN=".length());
    }
}
