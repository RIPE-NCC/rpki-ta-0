package net.ripe.rpki.ta.exception;


public class BadOptionsException extends Exception {
    private static final long serialVersionUID = 1L;

    public BadOptionsException(String message) {
        super(message);
    }

    public BadOptionsException(Exception e) {
        super(e);
    }
}
