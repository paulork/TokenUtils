package br.com.paulork.tokenutils;

import br.com.paulork.tokenutils.exceptions.PSegredoException;
import br.com.paulork.tokenutils.cripto.PCrypt;
import br.com.paulork.tokenutils.cripto.PSecrete;
import br.com.paulork.tokenutils.exceptions.PCryptException;
import br.com.paulork.tokenutils.exceptions.PTokenGeneratorException;
import com.google.gson.Gson;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class PTokenGenerator {

    private static long timeExpiration = 0L;

    public static String geraToken(Map<String, String> payLoad, PrivateKey privateKey, Options options, String caminhoSegredo) throws PTokenGeneratorException, PCryptException {
        options = processOptions(options);

        if (privateKey == null) {
            throw new PTokenGeneratorException("segredo não pode ser nulo.");
        }

        if (payLoad == null) {
            throw new PTokenGeneratorException("payLoad não pode ser nulo.");
        }

        if (options.getAlgorithm() == null) {
            throw new PTokenGeneratorException("Informe um algoritmo no options.");
        }

        String segredo;
        try {
            segredo = PSecrete.decryptSegredoFromFile(privateKey, caminhoSegredo);
        } catch (PSegredoException ex) {
            throw new PTokenGeneratorException(ex.getMessage());
        }
        List<String> segments = new ArrayList();

        segments.add(encodedHeader(options));
        segments.add(encodedPayload(payLoad, options, segredo));
        segments.add(encodedSignature(join(segments, "."), options.getAlgorithm(), segredo));

        return join(segments, ".");
    }

    public static long getExpiration() {
        return timeExpiration;
    }

    private static Options processOptions(Options options) {
        if (options == null) {
            return new Options().setAlgorithm(Algorithms.Cypher.AES);
        }

        if (options.getAlgorithm() == null) {
            options.setAlgorithm(Algorithms.Cypher.AES);
        }

        return options;
    }

    private static String encodedHeader(Options options) {
        long agora = System.currentTimeMillis() / 1000L;

        Map<String, String> map = new HashMap();
        map.put("typ", "JWT");
        map.put("alg", options.getAlgorithm().getNome());
        map.put("Time", Long.toString(agora));
        map.put("EncryptedPayLoad", Boolean.toString(options.getEncryptPayLoad()));

        Gson gson = new Gson();
        return encode(gson.toJson(map).getBytes());
    }

    private static String encodedPayload(Map<String, String> _claims, Options options, String segredo) throws PCryptException {
        Map<String, String> claims = new HashMap(_claims);

        processPayloadOptions(claims, options);

        Gson gson = new Gson();
        String encodedPayLoad;
        if (options.getEncryptPayLoad()) {
            byte[] encryptedPayLoad = null;
            try {
                PCrypt agoCrypt = new PCrypt(segredo);
                encryptedPayLoad = agoCrypt.encrypt(gson.toJson(claims));
            } catch (PCryptException ex) {
                throw new PCryptException("Erro ao criar Payload", ex);
            }
            encodedPayLoad = Base64.getUrlEncoder().encodeToString(encryptedPayLoad);
        } else {
            encodedPayLoad = Base64.getUrlEncoder().encodeToString(gson.toJson(claims).getBytes());
        }

        return encodedPayLoad;
    }

    private static String encodedSignature(String signingInput, Algorithms.Cypher algorithm, String segredo) throws PCryptException {
        byte[] signature = sign(algorithm, signingInput, segredo);
        return encode(signature);
    }

    private static void processPayloadOptions(Map<String, String> claims, Options options) {
        long now = System.currentTimeMillis() / 1000L;

        if (options.expirySeconds != null) {
            long exp = now + options.expirySeconds.intValue();
            claims.put("exp", Long.toString(exp));
            timeExpiration = exp;
        }
        if (options.notValidBeforeLeeway != null) {
            claims.put("nbf", Long.toString(now - options.notValidBeforeLeeway.intValue()));
        }
        if (options.isIssuedAt()) {
            claims.put("iat", Long.toString(now));
        }
        if (options.isJwtId()) {
            claims.put("jti", UUID.randomUUID().toString());
        }
    }

    private static String join(List<String> input, String on) {
        int size = input.size();
        int count = 1;
        StringBuilder joined = new StringBuilder();
        for (String string : input) {
            joined.append(string);
            if (count < size) {
                joined.append(on);
            }
            count++;
        }

        return joined.toString();
    }

    private static String encode(byte[] normal) {
        return Base64.getUrlEncoder().encodeToString(normal);
    }

    private static byte[] sign(Algorithms.Cypher algorithm, String msg, String segredo) throws PCryptException {
        switch (algorithm) {
            case AES:
                PCrypt agoCrypt = new PCrypt(segredo);

                return agoCrypt.encrypt(msg);
        }
        throw new PCryptException("Algoritmo ainda não suportado");
    }

    public static class Options {

        private Algorithms.Cypher algorithm;
        private Integer expirySeconds;
        private Integer notValidBeforeLeeway;
        private boolean issuedAt;
        private boolean jwtId;
        private boolean encryptPayLoad;

        public Algorithms.Cypher getAlgorithm() {
            return this.algorithm;
        }

        public Options setAlgorithm(Algorithms.Cypher algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Integer getExpirySeconds() {
            return this.expirySeconds;
        }

        public Options setExpirySeconds(Integer expirySeconds) {
            this.expirySeconds = expirySeconds;
            return this;
        }

        public Integer getNotValidBeforeLeeway() {
            return this.notValidBeforeLeeway;
        }

        public Options setNotValidBeforeLeeway(Integer notValidBeforeLeeway) {
            this.notValidBeforeLeeway = notValidBeforeLeeway;
            return this;
        }

        public boolean isIssuedAt() {
            return this.issuedAt;
        }

        public Options setIssuedAt(boolean issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public boolean isJwtId() {
            return this.jwtId;
        }

        public Options setJwtId(boolean jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        public boolean getEncryptPayLoad() {
            return this.encryptPayLoad;
        }

        public Options setEncryptPayLoad(boolean encryptPayLoad) {
            this.encryptPayLoad = encryptPayLoad;
            return this;
        }
    }
}
