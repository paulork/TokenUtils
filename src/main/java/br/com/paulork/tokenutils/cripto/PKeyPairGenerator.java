package br.com.paulork.tokenutils.cripto;

import br.com.paulork.tokenutils.Algorithms;
import br.com.paulork.tokenutils.exceptions.PKeyPairGeneratorException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PKeyPairGenerator {

    private static final String PUB_FILENAME = "key-pair-public";
    private static final String PRIV_FILENAME = "key-pair-private";

    public static KeyPair generate(Algorithms.KeyPairGenerator algoritmo, Algorithms.KeyPairGeneratorKeySize size) throws PKeyPairGeneratorException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            KeyPairGenerator keyPair = KeyPairGenerator.getInstance(algoritmo.getNome());
            keyPair.initialize(size.getKeySize(), random);
            return keyPair.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new PKeyPairGeneratorException("Erro ao gerar par de chaves", ex);
        }
    }

    public static KeyPair generateToFiles(String caminho, Algorithms.KeyPairGenerator algoritmo, Algorithms.KeyPairGeneratorKeySize size) throws PKeyPairGeneratorException {
        KeyPair keyPair = generate(algoritmo, size);

        if (keyPair != null) {
            try {
                savePublicFile(keyPair.getPublic(), caminho);
                savePrivateFile(keyPair.getPrivate(), caminho);
            } catch (IOException ex) {
                throw new PKeyPairGeneratorException("Erro ao criar arquivos das chaves", ex);
            }

            return keyPair;
        }

        return null;
    }

    private static void savePublicFile(PublicKey pubKey, String caminho) throws FileNotFoundException, IOException {
        byte[] key = pubKey.getEncoded();

        FileOutputStream keyfos = new FileOutputStream(caminho + "/" + PUB_FILENAME);
        keyfos.write(key);
        keyfos.close();
    }

    private static void savePrivateFile(PrivateKey privKey, String caminho) throws FileNotFoundException, IOException {
        byte[] key = privKey.getEncoded();

        FileOutputStream keyfos = new FileOutputStream(caminho + "/" + PRIV_FILENAME);
        keyfos.write(key);
        keyfos.close();
    }

    public static KeyPair fromFiles(String caminho, Algorithms.KeyPairGenerator algoritmo) throws PKeyPairGeneratorException {
        PrivateKey privKey = null;
        try {
            FileInputStream keyfis = new FileInputStream(caminho + "/" + PRIV_FILENAME);
            Throwable localThrowable6 = null;
            try {
                byte[] encKey = new byte[keyfis.available()];
                keyfis.read(encKey);

                PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
                KeyFactory keyFactory = KeyFactory.getInstance(algoritmo.getNome());
                privKey = keyFactory.generatePrivate(privKeySpec);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException localThrowable1) {
                localThrowable6 = localThrowable1;
                throw localThrowable1;
            } finally {
                if (keyfis != null) {
                    if (localThrowable6 != null) {
                        try {
                            keyfis.close();
                        } catch (Throwable localThrowable2) {
                            localThrowable6.addSuppressed(localThrowable2);
                        }
                    } else {
                        keyfis.close();
                    }
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new PKeyPairGeneratorException("Erro ao buscar chaves nos arquivos", ex);
        }

        byte[] encKey;
        PublicKey pubKey = null;
        try {
            FileInputStream keyfis = new FileInputStream(caminho + "/" + PUB_FILENAME);
            Throwable localThrowable1 = null;
            try {
                encKey = new byte[keyfis.available()];
                keyfis.read(encKey);

                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
                KeyFactory keyFactory = KeyFactory.getInstance(algoritmo.getNome());
                pubKey = keyFactory.generatePublic(pubKeySpec);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException localThrowable4) {
                localThrowable1 = localThrowable4;
                throw localThrowable4;
            } finally {
                if (keyfis != null) {
                    if (localThrowable1 != null) {
                        try {
                            keyfis.close();
                        } catch (Throwable localThrowable5) {
                            localThrowable1.addSuppressed(localThrowable5);
                        }
                    } else {
                        keyfis.close();
                    }
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new PKeyPairGeneratorException("Erro ao buscar chaves nos arquivos", ex);
        }

        return new KeyPair(pubKey, privKey);
    }
}
