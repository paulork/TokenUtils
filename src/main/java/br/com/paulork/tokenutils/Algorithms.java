package br.com.paulork.tokenutils;

public class Algorithms {

    public static String RSA = "RSA";

    public static enum KeyGenerator {
        
        AES("AES"),
        ARCFOUR("ARCFOUR"),
        Blowfish("Blowfish"),
        DES("DES"),
        DESede("DESede"),
        HmacMD5("HmacMD5"),
        RC2("RC2");

        private final String nome;

        private KeyGenerator(String nome) {
            this.nome = nome;
        }

        public String getNome() {
            return this.nome;
        }
    }

    public static enum KeyPairGenerator {
        DH("DH"), 
        DSA("DSA"), 
        RSA("RSA"), 
        RC("RC");

        private final String nome;

        private KeyPairGenerator(String nome) {
            this.nome = nome;
        }

        public String getNome() {
            return this.nome;
        }
    }

    public static enum KeyPairGeneratorKeySize {
        K_256(256), 
        K_512(512), 
        K_1024(1024), 
        K_2048(2048), 
        K_4096(4096);

        private final int keySize;

        private KeyPairGeneratorKeySize(int keySize) {
            this.keySize = keySize;
        }

        public int getKeySize() {
            return this.keySize;
        }
    }

    public static enum Signature {
        
        NONEwithRSA("NONEwithRSA"),
        MD2withRSA("MD2withRSA"),
        MD5withRSA("MD5withRSA"),
        SHA1withRSA("SHA1withRSA"),
        SHA256withRSA("SHA256withRSA"),
        SHA384withRSA("SHA384withRSA"),
        SHA512withRSA("SHA512withRSA"),
        NONEwithDSA("NONEwithDSA"),
        SHA1withDSA("SHA1withDSA"),
        NONEwithECDSA("NONEwithECDSA"),
        SHA1withECDSA("SHA1withECDSA"),
        SHA256withECDSA("SHA256withECDSA"),
        SHA384withECDSA("SHA384withECDSA"),
        SHA512withECDSA("SHA512withECDSA");

        private final String nome;

        private Signature(String nome) {
            this.nome = nome;
        }

        public String getNome() {
            return this.nome;
        }

        public static boolean existe(String algoritmo) {

            for (Signature alg : values()) {
                if (alg.getNome().equals(algoritmo)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static enum Cypher {
        
        AES("AES"),
        AESWrap("AESWrap"),
        ARCFOUR("ARCFOUR"),
        Blowfish("Blowfish"),
        CCM("CCM"),
        DES("DES"),
        DESede("DESede"),
        DESedeWrap("DESedeWrap"),
        ECIES("ECIES"),
        GCM("GCM"),
        RC2("RC2"),
        RC4("RC4"),
        RC5("RC5"),
        RSA("RSA");

        private final String nome;

        private Cypher(String nome) {
            this.nome = nome;
        }

        public String getNome() {
            return this.nome;
        }

        public static boolean existe(String algoritmo) {
            for (Cypher alg : values()) {
                if (alg.getNome().equals(algoritmo)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static enum Mac {
        
        HmacMD5("HmacMD5"),
        HmacSHA1("HmacSHA1"),
        HmacSHA256("HmacSHA256"),
        HmacSHA384("HmacSHA384"),
        HmacSHA512("HmacSHA512");

        private final String nome;

        private Mac(String nome) {
            this.nome = nome;
        }

        public String getNome() {
            return this.nome;
        }

        public static boolean existe(String algoritmo) {
            for (Mac alg : values()) {
                if (alg.getNome().equals(algoritmo)) {
                    return true;
                }
            }
            return false;
        }
    }
}
