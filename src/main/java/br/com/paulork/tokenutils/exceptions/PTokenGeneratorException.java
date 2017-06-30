package br.com.paulork.tokenutils.exceptions;

public class PTokenGeneratorException extends Exception {

    public PTokenGeneratorException() {
    }

    public PTokenGeneratorException(String msg) {
        super(msg);
    }

    public PTokenGeneratorException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
