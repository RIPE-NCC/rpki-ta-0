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
package net.ripe.rpki.ta.serializers;


import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.domain.response.ErrorResponse;
import net.ripe.rpki.ta.domain.response.RevocationResponse;
import net.ripe.rpki.ta.domain.response.SigningResponse;
import net.ripe.rpki.ta.domain.response.TrustAnchorResponse;


public class TrustAnchorResponseSerializer extends Serializer<TrustAnchorResponse> {

    protected XStreamXmlSerializerBuilder<TrustAnchorResponse> configureBuilder(XStreamXmlSerializerBuilder<TrustAnchorResponse> builder) {
        builder.withAliasType("TrustAnchorResponse", TrustAnchorResponse.class);
        builder.withAliasType("SigningResponse", SigningResponse.class);
        builder.withAliasType("RevocationResponse", RevocationResponse.class);
        builder.withAliasType("ErrorResponse", ErrorResponse.class);

        builder.withAliasType("X509ResourceCertificate", X509ResourceCertificate.class);
        builder.withAliasType("CRL", X509Crl.class);
        builder.withAliasType("Manifest", ManifestCms.class);
        builder.withAliasType("Roa", RoaCms.class);
        builder.withAliasType("RoaPrefix", RoaPrefix.class);
        return builder;
    }

    protected Class<TrustAnchorResponse> clazz() {
        return TrustAnchorResponse.class;
    }


}
