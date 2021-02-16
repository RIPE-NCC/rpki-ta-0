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
package net.ripe.rpki.ta.domain.request;


import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import org.joda.time.DateTimeUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TrustAnchorRequest {

    private static final long serialVersionUID = 1L;

    private final Long creationTimestamp;
    private final URI taCertificatePublicationUri;
    private final List<TaRequest> taRequests;
    private final X509CertificateInformationAccessDescriptor[] siaDescriptors;

    public TrustAnchorRequest(URI taCertificatePublicationUri, X509CertificateInformationAccessDescriptor[] siaDescriptors, List<TaRequest> taRequests) {
        this.creationTimestamp = DateTimeUtils.currentTimeMillis();
        this.taCertificatePublicationUri = taCertificatePublicationUri;
        this.taRequests = taRequests;
        this.siaDescriptors = siaDescriptors;
    }

    public Long getCreationTimestamp() {
        return creationTimestamp;
    }

    public URI getTaCertificatePublicationUri() {
        return taCertificatePublicationUri;
    }

    public List<TaRequest> getTaRequests() {
        return taRequests;
    }

    public X509CertificateInformationAccessDescriptor[] getSiaDescriptors() {
        return siaDescriptors;
    }
}
