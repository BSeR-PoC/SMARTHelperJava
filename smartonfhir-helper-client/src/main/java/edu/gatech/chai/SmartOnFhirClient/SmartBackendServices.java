package edu.gatech.chai.SmartOnFhirClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import edu.gatech.chai.common.UtilitiesV1;
import io.jsonwebtoken.Jwts;

/**
 * SMARTonFHIR Backend Services
 *
 */
@Component
public class SmartBackendServices 
{
    private String privateKeyFilePath;
    private String publicKeyFilePath;
    private String jwksFilePath;
    private String keystoreFilePath;
    private String clientId;
    private String tokenUrl;
    private String fhirServerUrl;
    private Long jwtExp;
    private String accessToken = null;
    private Long tokenExpiration = 0L;

    public SmartBackendServices() {
        publicKeyFilePath = System.getenv("PUBLIC_KEY_FILE");
        if (publicKeyFilePath == null || publicKeyFilePath.isBlank()) {
            publicKeyFilePath = "publicKey";
        }

        privateKeyFilePath = System.getenv("PRIVATE_KEY_FILE");
        if (privateKeyFilePath == null || privateKeyFilePath.isBlank()) {
            privateKeyFilePath = ".privateKey";
        }

        jwksFilePath = System.getenv("JWKS_FILE");
        if (jwksFilePath == null || jwksFilePath.isBlank()) {
            jwksFilePath = "jwks.json";
        }

        keystoreFilePath = System.getenv("KEYSTORE_FILE");
        if (keystoreFilePath == null || keystoreFilePath.isBlank()) {
            keystoreFilePath = "bserKeystore.jks";
        }

        String myClientId = System.getenv("CLIENTID");
        if (myClientId == null || myClientId.isBlank()) {
            setClientId("no-clientid");
        } else {
            setClientId(myClientId);
        }

        String defaultfhirServerUrl = System.getenv("FHIRSERVER_URL");
        if (defaultfhirServerUrl == null || defaultfhirServerUrl.isBlank()) {
            setFhirServerUrl("http://no-fhir-server/");
        } else {
            setFhirServerUrl(defaultfhirServerUrl);
        }

        String defaultTokenUrl = System.getenv("TOKENURL");
        if (defaultTokenUrl == null || defaultTokenUrl.isBlank()) {
            try {
                setTokenUrl(UtilitiesV1.findTokenUrl(getFhirServerUrl()));
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            // find the 
            setTokenUrl(defaultTokenUrl);
        }

        String defaultJwtExp = System.getenv("JWT_EXP");
        if (defaultJwtExp == null || defaultJwtExp.isBlank()) {
            jwtExp = 300L;
        } else {
            jwtExp = Long.valueOf(defaultJwtExp);
        }
    }

    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(String clientId) {
        // First try to get token URL from metadata

        this.clientId = clientId;
    }

    public String getTokenUrl() {
        return this.tokenUrl;
    }

    public void setTokenUrl(String tokenUrl) {
        this.tokenUrl = tokenUrl;
    }

    public String getFhirServerUrl() {
        return this.fhirServerUrl;
    }

    public void setFhirServerUrl(String fhirServerUrl) {
        this.fhirServerUrl = fhirServerUrl;
    }

    public String getPublicKey() throws IOException {
        Path path = Path.of(publicKeyFilePath);
        return Files.readString(path);
    }

    /***
     * getJWKS() read JSON Web Key Set (JWKS) from local file.
     * @return JWKS
     * @throws IOException
     */
    public String getJWKS() throws IOException {
        Path path = Path.of(jwksFilePath);
        String jwk = Files.readString(path);
        String jwks = null;

        // currently, we only have one jwk.
        if (jwk != null && !jwk.isBlank()) {
            jwks = "{\"keys\": [" + jwk + "]}"; 
        }

        return jwks; 
    }

    public String generateJWTS() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        InputStream inputStream = new FileInputStream(new File(keystoreFilePath));

        ks.load(inputStream, "changeme".toCharArray());
        Key key = ks.getKey("smartonfhir072222", "changeme".toCharArray());
        inputStream.close();

        // Build JWTS
        // Build header
        Map<String, Object> header = new HashMap<String, Object>();
        // header.put("alg", SignatureAlgorithm.RS256.getValue());

        // TODO: Get kid from the JWK.
        header.put("kid", "bserengine072222");
        header.put("typ", "JWT");
        
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("iss", getClientId());
        claims.put("sub", getClientId());
        claims.put("aud", getTokenUrl());

        // set expiration time
        Long currentTime = new Date().getTime()/1000;
        claims.put("exp", currentTime + jwtExp);
        claims.put("jti", currentTime.toString());

        return Jwts.builder().setHeader(header).setClaims(claims).signWith(key).compact();
    }

    public String getAccessToken(String tokenServerUrl) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        // check the token expiration if token is not null
        if (accessToken != null) {
            Long currentTime = new Date().getTime()/1000;
            if (currentTime < tokenExpiration - 15) { // putting 15 sec buffer
                return accessToken;
            }
        }

        if (tokenServerUrl == null || tokenServerUrl.isBlank()) {
            tokenServerUrl = getTokenUrl();
        }

        RestTemplate restTemplate = new RestTemplate();
        
        HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        MultiValueMap<String, String> formDataMap = new LinkedMultiValueMap<>();
        formDataMap.add("grant_type", "client_credentials");
        formDataMap.add("scope", "system/Patient.read");
        formDataMap.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        formDataMap.add("client_assertion", generateJWTS());

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formDataMap, headers);
        ResponseEntity<String> response = restTemplate.exchange(tokenServerUrl, HttpMethod.POST, entity, String.class);
        
        HttpStatus responseStatus = response.getStatusCode();
        if (responseStatus == HttpStatus.CREATED || responseStatus == HttpStatus.OK) {
            accessToken = response.getBody();
            JSONObject tokenJson = new JSONObject(accessToken);
            Long currentTime = new Date().getTime()/1000;
            tokenExpiration = currentTime + tokenJson.getLong("expires_in");

            return accessToken;
        } else {
            return null;
        }
    }
    
}
