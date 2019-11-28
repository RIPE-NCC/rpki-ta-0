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
package net.ripe.rpki.ta.serializers.legacy;


import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.math.BigInteger;

public abstract class SignedObjectTracker implements Serializable {

    private static final long serialVersionUID = 1L;

    private final CertificateRepositoryObject certificateRepositoryObject;

    private final String fileName;

    private DateTime revocationTime;

    private DateTime notValidAfter;


    public SignedObjectTracker(CertificateRepositoryObject certificateRepositoryObject, DateTime notValidAfter) {
        Validate.notNull(certificateRepositoryObject, "certificateRepositoryObject is required");
        this.fileName = null;
        this.certificateRepositoryObject = certificateRepositoryObject;
        this.revocationTime = null;
        this.notValidAfter = notValidAfter;
    }

    public SignedObjectTracker(String fileName, CertificateRepositoryObject certificateRepositoryObject, DateTime notValidAfter) {
        Validate.notEmpty(fileName, "fileName is required");
        Validate.notNull(certificateRepositoryObject, "certificateRepositoryObject is required");
        this.fileName = fileName;
        this.certificateRepositoryObject = certificateRepositoryObject;
        this.revocationTime = null;
        this.notValidAfter = notValidAfter;
    }

    public String getFileName() {
        return fileName;
    }

    public CertificateRepositoryObject getCertificateRepositoryObject() {
        return certificateRepositoryObject;
    }

    public void revoke() {
        if (revocationTime == null) {
            revocationTime = now();
        }
    }

    public boolean shouldAppearInCrl() {
        return (isRevoked() && !isExpired());
    }

    public boolean isPublishable() {
        return !isExpired() && !isRevoked();
    }

    private boolean isExpired() {
        return now().isAfter(notValidAfter);
    }

    private DateTime now() {
        return DateTime.now(DateTimeZone.UTC);
    }

    public boolean isRevoked() {
        return revocationTime != null;
    }

    public DateTime getRevocationTime() {
        return revocationTime;
    }

    public abstract BigInteger getCertificateSerial();
}
