package br.com.paulork.tokenutils;

import br.com.paulork.tokenutils.cripto.PCrypt;
import br.com.paulork.tokenutils.cripto.PSecrete;
import br.com.paulork.tokenutils.exceptions.PCryptException;
import br.com.paulork.tokenutils.exceptions.PSegredoException;
import br.com.paulork.tokenutils.exceptions.PTokenVerifierException;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

public class PTokenVerifier {

    public static Map<String, String> verify(String token, PrivateKey privateKey, String caminhoSegredo) throws PTokenVerifierException {
        if ((token == null) || ("".equals(token))) {
            throw new PTokenVerifierException("Token não pode ser nulo ou vazio.");
        }
        if (privateKey == null) {
            throw new PTokenVerifierException("Chave Privada não pode ser nula.");
        }

        String[] pieces = token.split("\\.");
        if (pieces.length != 3) {
            throw new PTokenVerifierException("Token com segmentos inválidos: " + pieces.length);
        }

        String segredo;
        try {
            segredo = PSecrete.decryptSegredoFromFile(privateKey, caminhoSegredo);
        } catch (PSegredoException ex) {
            throw new PTokenVerifierException(ex.getMessage());
        }

        String encodedHeader = pieces[0];
        String encodedPayLoad = pieces[1];
        String encodedSignature = pieces[2];

        Map<String, String> header = processHeader(encodedHeader);
        Algorithms.Cypher algorithm = Algorithms.Cypher.valueOf((String) header.get("alg"));
        Map<String, String> payLoad = processPayload(encodedPayLoad, header, segredo);
        verifyExpiration(payLoad);
        verifySignature(encodedSignature, algorithm, segredo, encodedHeader + "." + encodedPayLoad);

        return payLoad;
    }

    private static Map<String, String> processHeader(String encodedHeader) throws PTokenVerifierException {
        try {
            Map<String, String> header = decodeAndParse(encodedHeader);
            if ((!header.containsKey("alg")) || ((header.containsKey("alg")) && (((String) header.get("alg")).isEmpty()))) {
                throw new PTokenVerifierException("Algoritmo não expecificado no Header. Chave 'alg' inexistente.");
            }
            if (!Algorithms.Cypher.existe((String) header.get("alg"))) {
                throw new PTokenVerifierException("Algoritmo incompatível. '" + (String) header.get("alg") + "' não é um algoritmo compatível.");
            }
            return header;
        } catch (IllegalStateException | JsonSyntaxException | IllegalArgumentException e) {
            throw new PTokenVerifierException("Erro ao processar Header", e);
        }
    }

    private static Map<String, String> processPayload(String encodedPayLoad, Map<String, String> header, String segredo) throws PTokenVerifierException {
        try {
            byte[] decodedPayLoad = decode(encodedPayLoad);
            String normalPayLoad;
            if ((header.containsKey("EncryptedPayLoad")) && (((String) header.get("EncryptedPayLoad")).equals("true"))) {
                PCrypt agoCrypt = new PCrypt(segredo);
                normalPayLoad = new String(agoCrypt.decrypt(decodedPayLoad));
            } else {
                normalPayLoad = new String(decodedPayLoad);
            }

            return parse(normalPayLoad);
        } catch (JsonSyntaxException | PCryptException | IllegalArgumentException ex) {
            throw new PTokenVerifierException("Erro ao processar Payload", ex);
        }
    }

    private static void verifySignature(String encodedSignature, Algorithms.Cypher algorithm, String segredo, String originalSign) throws PTokenVerifierException {
        try {
            byte[] signature = decode(encodedSignature);
            PCrypt agoCrypt = new PCrypt(segredo);
            byte[] decrypted = agoCrypt.decrypt(signature);
            boolean passou = Arrays.equals(decrypted, originalSign.getBytes(Charset.forName("UTF-8")));
            if (!passou) {
                throw new PTokenVerifierException("Assinatura inválida.");
            }
        } catch (PCryptException | IllegalArgumentException ex) {
            throw new PTokenVerifierException("Erro ao processar signature.", ex);
        }
    }

    private static void verifyExpiration(Map<String, String> payLoad) throws PTokenVerifierException {
        if (payLoad.containsKey("exp")) {
            long expiration = Long.parseLong((String) payLoad.get("exp"));
            if (System.currentTimeMillis() / 1000L >= expiration) {
                throw new PTokenVerifierException("Token expirado.");
            }
        }
    }

    private static Map<String, String> decodeAndParse(String b64String) throws IllegalArgumentException, JsonSyntaxException, IllegalStateException {
        return parse(new String(decode(b64String)));
    }

    private static byte[] decode(String b64String) throws IllegalArgumentException {
        return Base64.getUrlDecoder().decode(b64String);
    }

    private static Map<String, String> parse(String jsonString) throws JsonSyntaxException {
        Gson gson = new Gson();
        Type tipo = new TypeToken<Map<String, String>>() {}.getType();
        return (Map) gson.fromJson(jsonString, tipo);
    }
}
