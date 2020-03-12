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



import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.domain.Revocation;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.serializers.legacy.SignedObjectTracker;

import javax.security.auth.x500.X500Principal;

public class TAStateSerializer extends Serializer<TAState> {

    protected XStreamXmlSerializerBuilder<TAState> configureBuilder(XStreamXmlSerializerBuilder<TAState> builder) {
        return builder
                .withAliasType("TA", TAState.class)
                .withAliasType("revocation", Revocation.class)
                .withAllowedType(Config.class)
                .withAllowedType(X500Principal.class)
                .withAllowedType(X509Crl.class)
                .withAllowedTypeHierarchy(SignedObjectTracker.class);
    }

    protected Class<TAState> clazz() {
        return TAState.class;
    }
}
