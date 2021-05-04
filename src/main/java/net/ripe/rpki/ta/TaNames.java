/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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
