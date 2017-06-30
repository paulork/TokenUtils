package br.com.paulork.tokenutils.cripto;

import br.com.paulork.tokenutils.Algorithms;
import br.com.paulork.tokenutils.exceptions.PSignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class PSignature {

    public static byte[] sign(byte[] str, PrivateKey privateKey, Algorithms.Signature algoritmo) throws PSignatureException {
        try {
            Signature sign = Signature.getInstance(algoritmo.getNome());
            sign.initSign(privateKey);
            sign.update(str);
            return sign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            throw new PSignatureException("Erro ao criar assinatura.", ex);
        }
    }

    public static boolean verify(byte[] str, byte[] originalSig, PublicKey publicKey, Algorithms.Signature algoritmo) throws PSignatureException {
        try {
            Signature sign = Signature.getInstance(algoritmo.getNome());
            sign.initVerify(publicKey);
            sign.update(originalSig);
            return sign.verify(str);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            throw new PSignatureException("Erro ao verificar assinatura.", ex);
        }
    }
}
