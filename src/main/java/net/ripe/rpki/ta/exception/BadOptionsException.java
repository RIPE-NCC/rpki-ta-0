package net.ripe.rpki.ta.exception;


public class BadOptionsException extends Exception {
    public BadOptionsException(String message) {
        super(message);
    }

    public BadOptionsException(Exception e) {
        super(e);
    }
}
