package net.ripe.rpki.ta.exception;

public class BadConfigException extends Exception {
    private static final long serialVersionUID = 1L;

    public BadConfigException(String message) {
        super(message);
    }
}
