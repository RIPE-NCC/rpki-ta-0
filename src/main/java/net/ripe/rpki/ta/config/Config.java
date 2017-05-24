package net.ripe.rpki.ta.config;

import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class Config {

    private X500Principal trustAnchorName;
    private URI taCertificatePublicationUri;
    private URI taProductsPublicationUri;
    private String keystoreProvider;
    private String keypairGeneratorProvider;
    private String signatureProvider;
    private String keystoreType;
    private String persistentStorageDir;
    private Period minimumValidityPeriod;
    private Period updatePeriod;

    public Config() {
    }

    public X500Principal getTrustAnchorName() {
        return trustAnchorName;
    }

    public void setTrustAnchorName(X500Principal trustAnchorName) {
        this.trustAnchorName = trustAnchorName;
    }

    public URI getTaCertificatePublicationUri() {
        return taCertificatePublicationUri;
    }

    public void setTaCertificatePublicationUri(URI taCertificatePublicationUri) {
        this.taCertificatePublicationUri = taCertificatePublicationUri;
    }

    public String getKeystoreProvider() {
        return keystoreProvider;
    }

    public void setKeystoreProvider(String keystoreProvider) {
        this.keystoreProvider = keystoreProvider;
    }

    public String getKeypairGeneratorProvider() {
        return keypairGeneratorProvider;
    }

    public void setKeypairGeneratorProvider(String keypairGeneratorProvider) {
        this.keypairGeneratorProvider = keypairGeneratorProvider;
    }

    public String getSignatureProvider() {
        return signatureProvider;
    }

    public void setSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public String getPersistentStorageDir() {
        return persistentStorageDir;
    }

    public void setPersistentStorageDir(String persistentStorageDir) {
        this.persistentStorageDir = persistentStorageDir;
    }

    public Period getMinimumValidityPeriod() {
        return minimumValidityPeriod;
    }

    public void setMinimumValidityPeriod(Period minimumValidityPeriod) {
        this.minimumValidityPeriod = minimumValidityPeriod;
    }

    public Period getUpdatePeriod() {
        return updatePeriod;
    }

    public void setUpdatePeriod(Period updatePeriod) {
        this.updatePeriod = updatePeriod;
    }

    public URI getTaProductsPublicationUri() {
        return taProductsPublicationUri;
    }

    public void setTaProductsPublicationUri(URI taProductsPublicationUri) {
        this.taProductsPublicationUri = taProductsPublicationUri;
    }
}
