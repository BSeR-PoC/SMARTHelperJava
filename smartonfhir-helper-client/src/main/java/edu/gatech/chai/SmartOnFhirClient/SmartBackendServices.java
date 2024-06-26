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
import org.springframework.http.HttpStatusCode;
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
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SmartBackendServices.class);

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
    private boolean isActive = true;
    private boolean disabled = false;

    // Map to manage tokenUrl, token, and token expiration
    private Map<String, String> tokenUrlMap;
    private Map<String, String> tokenMap;
    private Map<String, Long> tokenExpirationMap;

    public SmartBackendServices() {
        this(null);
    }

    public SmartBackendServices(String fhirServerUrl) {
        tokenUrlMap = new HashMap<String, String>();
        tokenMap = new HashMap<String, String>();
        tokenExpirationMap = new HashMap<String, Long>();

        // Even if SMART Backend Service is disabled, 
        // we should still publish the public key.
        jwksFilePath = System.getenv("JWKS_FILE");
        if (jwksFilePath == null || jwksFilePath.isBlank()) {
            jwksFilePath = "jwks.json";
        }

        String disabledString = System.getenv("SMARTONFHIR");
        if (disabledString != null && !disabledString.isBlank()) {
            if ("disabled".equalsIgnoreCase(disabledString)) {
                disabled = true;
                return;
            }
        }
        publicKeyFilePath = System.getenv("PUBLIC_KEY_FILE");
        if (publicKeyFilePath == null || publicKeyFilePath.isBlank()) {
            publicKeyFilePath = "publicKey";
        }

        privateKeyFilePath = System.getenv("PRIVATE_KEY_FILE");
        if (privateKeyFilePath == null || privateKeyFilePath.isBlank()) {
            privateKeyFilePath = ".privateKey";
        }

        keystoreFilePath = System.getenv("KEYSTORE_FILE");
        if (keystoreFilePath == null || keystoreFilePath.isBlank()) {
            keystoreFilePath = "bserKeystore.jks";
        }

        String myClientId = System.getenv("CLIENTID");
        if (myClientId == null || myClientId.isBlank()) {
            isActive = false;
        } else {
            setClientId(myClientId);
        }

        String defaultfhirServerUrl = System.getenv("FHIRSERVER_URL");
        if (fhirServerUrl == null || fhirServerUrl.isBlank()) {
            if (defaultfhirServerUrl != null && !defaultfhirServerUrl.isBlank()) {
                setFhirServerUrl(defaultfhirServerUrl);
            } else {
                isActive = false;
            }
        } else {
            setFhirServerUrl(fhirServerUrl);
        }

        // String defaultTokenUrl = System.getenv("TOKENURL");
        // if (defaultTokenUrl == null || defaultTokenUrl.isBlank()) {
        //     try {
        //         setTokenUrl(UtilitiesV1.findTokenUrl(getFhirServerUrl()));
        //     } catch (IOException e) {
        //         e.printStackTrace();
        //         isActive = false;
        //     }
        // } else {
        //     // save the predefined token url
        //     setTokenUrl(defaultTokenUrl);
        // }

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

    public SmartBackendServices setFhirServerUrl(String fhirServerUrl) {
        if (fhirServerUrl == null || fhirServerUrl.isBlank()) {
            logger.debug("Can't change the server to null or empty");
            isActive = false;
            return this;
        }

        if (!fhirServerUrl.startsWith("http")) {
            logger.debug("Not a valid FHIR Server URL");
            isActive = false;
            return this;
        }

        if (fhirServerUrl.equals(this.fhirServerUrl)) {
            // This is same fhir server. No need to set.
            logger.debug("Already set to this FHIR server (" + fhirServerUrl + ")");
            return this;
        }

        // We are changing the fhir server URL. We may already had this before. 
        // If so, return those as setting token URL and token are expensive.
        String existingTokenUrl = tokenUrlMap.get(fhirServerUrl);
        if (existingTokenUrl != null && !existingTokenUrl.isBlank()) {
            setTokenUrl(existingTokenUrl);
            setAccessToken(tokenMap.get(fhirServerUrl));
            setTokenExpiration(tokenExpirationMap.get(fhirServerUrl));
            logger.debug("FHIR server (" + fhirServerUrl + ") has already beeing set up for the token.");

            return this;
        }

        this.fhirServerUrl = fhirServerUrl;
        String newTokenUrl = UtilitiesV1.findTokenUrl(fhirServerUrl);
        if (newTokenUrl == null || newTokenUrl.isBlank()) {
            logger.debug("The new FHIR server may not have metadata setup correctly. Failed to get the token URL");
            isActive = false;
            return this;
        }

        setTokenUrl(newTokenUrl);

        // Since the fhir server is set. Reset token and expiration time
        setAccessToken(null);
        setTokenExpiration(0L);

        // set up the token management maps
        tokenUrlMap.put(fhirServerUrl, newTokenUrl);
        tokenMap.put(fhirServerUrl, this.accessToken);
        tokenExpirationMap.put(fhirServerUrl, this.tokenExpiration);

        isActive = true;
        
        return this;
    }

    public String getPublicKey() throws IOException {
        Path path = Path.of(publicKeyFilePath);
        return Files.readString(path);
    }

    public boolean isActive() {
        if (disabled) {
            return false;
        }
        
        return this.isActive;
    }

    /***
     * getJWKS() read JSON Web Key Set (JWKS) from local file.
     * @return JWKS
     * @throws IOException
     */
    public String getJWKS() throws IOException, NullPointerException {
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

    public void setTokenExpiration(Long tokenExpiration) {
        this.tokenExpiration = tokenExpiration;
    }
    
    public Long getTokenExpiration() {
        return this.tokenExpiration;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getAccessToken(String tokenServerUrl) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (!isActive) {
            // The backend access token retrieval is not configured.
            logger.info("SMARTonFHIR Backend Services is not configured to run.");
            return null;
        }

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
        
        HttpStatusCode responseStatus = response.getStatusCode();
        if (responseStatus == HttpStatus.CREATED || responseStatus == HttpStatus.OK) {
            accessToken = response.getBody();
            JSONObject tokenJson = new JSONObject(accessToken);
            Long currentTime = new Date().getTime()/1000;
            tokenExpiration = currentTime + tokenJson.getLong("expires_in");

            tokenUrlMap.put(this.fhirServerUrl, tokenServerUrl);
            tokenMap.put(this.fhirServerUrl, this.accessToken);
            tokenExpirationMap.put(this.fhirServerUrl, this.tokenExpiration);
    
            return accessToken;
        } else {
            return null;
        }
    }
    
}
