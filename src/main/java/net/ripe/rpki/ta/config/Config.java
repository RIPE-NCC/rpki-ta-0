package net.ripe.rpki.ta.config;


import lombok.Data;
import lombok.NoArgsConstructor;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

@NoArgsConstructor
@Data
public class Config {

    private X500Principal trustAnchorName;
    private URI taCertificatePublicationUri;
    private URI taProductsPublicationUri;
    private URI notificationUri;
    private String keystoreProvider;
    private String keypairGeneratorProvider;
    private String signatureProvider;
    private String keystoreType;
    private String persistentStorageDir;
    private Period minimumValidityPeriod;
    private Period updatePeriod;
}
