package br.com.paulork.tokenutils.exceptions;

public class PTokenVerifierException extends Exception {

    public PTokenVerifierException() {
    }

    public PTokenVerifierException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public PTokenVerifierException(String msg) {
        super(msg);
    }
}
