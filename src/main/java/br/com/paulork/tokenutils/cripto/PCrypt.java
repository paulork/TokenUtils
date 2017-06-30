package br.com.paulork.tokenutils.cripto;

import br.com.paulork.tokenutils.exceptions.PCryptException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PCrypt {

    private Key key;
    private final IvParameterSpec IV = new IvParameterSpec(SALT);
    private static final byte[] SALT = "abcdqwerabcdqwer".getBytes(Charset.forName("UTF-8"));

    public PCrypt(String segredo) {
        gerarKey(segredo);
    }

    private void gerarKey(String password) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, 20, 128);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            this.key = secret;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(PCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public byte[] encrypt(String toEncrypt) throws PCryptException {
        byte[] retorno = null;

        try {
            Cipher c1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c1.init(1, this.key, this.IV);
            retorno = c1.doFinal(toEncrypt.getBytes(Charset.forName("UTF-8")));
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new PCryptException("Erro ao Encryptar", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(PCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }

        return retorno;
    }

    public byte[] decrypt(byte[] encrypted) throws PCryptException {
        byte[] retorno = null;
        try {
            Cipher c1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c1.init(2, this.key, this.IV);
            retorno = c1.doFinal(encrypted);
        } catch (BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException ex) {
            throw new PCryptException("Erro ao Decryptar", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(PCrypt.class.getName()).log(Level.SEVERE, null, ex);
        }

        return retorno;
    }
}
