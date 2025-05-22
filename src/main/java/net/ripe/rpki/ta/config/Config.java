package net.ripe.rpki.ta.config;

import com.google.common.base.Preconditions;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;


@Getter
@EqualsAndHashCode
@ToString
public class Config {
    @Setter
    private X500Principal trustAnchorName;

    @Setter
    private String keystoreProvider;

    @Setter
    private String keypairGeneratorProvider;

    @Setter
    private String signatureProvider;

    @Setter
    private String keystoreType;

    @Setter
    private String persistentStorageDir;

    @Setter
    private URI taCertificatePublicationUri;

    @Setter
    private URI taProductsPublicationUri;

    @Setter
    private URI notificationUri;

    private Period minimumValidityPeriod;

    public Period getMinimumValidityPeriod() {
        return Preconditions.checkNotNull(minimumValidityPeriod, "Manifest and CRL validity period cannot be null");
    }

    public void setMinimumValidityPeriod(Period minimumValidityPeriod) {
        this.minimumValidityPeriod = Preconditions.checkNotNull(minimumValidityPeriod, "Manifest and CRL validity period cannot be null");
    }

}
