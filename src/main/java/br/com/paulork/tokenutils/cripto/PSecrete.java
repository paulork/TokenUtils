package br.com.paulork.tokenutils.cripto;

import br.com.paulork.tokenutils.exceptions.PSegredoException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PSecrete {

    private static final String SEGREDO_FILENAME = "segredo-encrypted";

    public static String decryptSegredoFromFile(PrivateKey privateKey, String caminhoSegredo) throws PSegredoException {
        String retorno = new String();
        byte[] encKey = null;
        try {
            FileInputStream keyfis = new FileInputStream(caminhoSegredo + "/" + SEGREDO_FILENAME);
            Throwable localThrowable3 = null;
            try {
                encKey = new byte[keyfis.available()];
                keyfis.read(encKey);
            } catch (IOException localThrowable1) {
                localThrowable3 = localThrowable1;
                throw localThrowable1;
            } finally {
                if (keyfis != null) {
                    if (localThrowable3 != null) {
                        try {
                            keyfis.close();
                        } catch (IOException localThrowable2) {
                            localThrowable3.addSuppressed(localThrowable2);
                        }
                    } else {
                        keyfis.close();
                    }
                }
            }
        } catch (IOException ex) {
            throw new PSegredoException("Erro ao buscar segredo no arquivo", ex);
        }
        
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(2, privateKey);
            retorno = new String(c.doFinal(encKey), Charset.forName("UTF-8"));
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new PSegredoException("Erro ao Decifrar segredo", ex);
        }

        return retorno;
    }

    public static void generateSegredoToFile(PublicKey publicKey, String caminhoSegredo, String segredo) throws PSegredoException {
        byte[] encKey;

        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(1, publicKey);
            encKey = c.doFinal(segredo.getBytes(Charset.forName("UTF-8")));
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new PSegredoException("Erro ao Cifrar segredo", ex);
        }

        try {
            FileOutputStream keyfos = new FileOutputStream(caminhoSegredo + "/" + SEGREDO_FILENAME);
            Throwable localThrowable3 = null;
            try {
                keyfos.write(encKey);
            } catch (IOException localThrowable1) {
                localThrowable3 = localThrowable1;
                throw localThrowable1;
            } finally {
                if (keyfos != null) {
                    if (localThrowable3 != null) {
                        try {
                            keyfos.close();
                        } catch (IOException localThrowable2) {
                            localThrowable3.addSuppressed(localThrowable2);
                        }
                    } else {
                        keyfos.close();
                    }
                }
            }
        } catch (FileNotFoundException ex) {
            throw new PSegredoException("Erro ao criar arquivo de segredo", ex);
        } catch (IOException ex) {
            throw new PSegredoException("Erro ao criar arquivo de segredo", ex);
        }
    }
}
