package br.com.paulork.tokenutils.exceptions;

public class PSignatureException extends Exception {

    public PSignatureException() {
    }

    public PSignatureException(String msg) {
        super(msg);
    }

    public PSignatureException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
