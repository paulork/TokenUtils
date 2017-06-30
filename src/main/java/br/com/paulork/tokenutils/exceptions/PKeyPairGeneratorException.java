package br.com.paulork.tokenutils.exceptions;

public class PKeyPairGeneratorException extends Exception {

    public PKeyPairGeneratorException() {
    }

    public PKeyPairGeneratorException(String msg) {
        super(msg);
    }

    public PKeyPairGeneratorException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
