package edu.gatech.chai.common;

import java.io.IOException;

import org.hl7.fhir.r4.model.CapabilityStatement;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.UriType;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestComponent;
import org.hl7.fhir.r4.model.CapabilityStatement.CapabilityStatementRestSecurityComponent;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonParseException;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.IParser;

public class UtilitiesV1 {
    public static final FhirContext myFhirContext = FhirContext.forR4(); 

    public static String findTokenUrl(String fhirServerUrl) throws JsonParseException, IOException, RestClientException {
        String fhirMetaUrl;
        String retToken = null;
        
        RestTemplate restTemplate = new RestTemplate();

        // First try with .well-known/smart-configuration
        if (fhirServerUrl.endsWith("/")) {
            fhirMetaUrl = fhirServerUrl+".well-known/smart-configuration";
        } else {
            fhirMetaUrl = fhirServerUrl+"/.well-known/smart-configuration";
        }

        HttpHeaders headers = new HttpHeaders();
		headers.setContentType(new MediaType("application", "json+fhir"));
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(fhirMetaUrl, HttpMethod.GET, requestEntity, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            JSONObject smartConfigJson = new JSONObject(response.getBody());
            return smartConfigJson.get("token_endpoint").toString();
        } else {
            // Get token url from FHIR standard capability statement

            if (fhirServerUrl.endsWith("/")) {
                fhirMetaUrl = fhirServerUrl+"metadata";
            } else {
                fhirMetaUrl = fhirServerUrl+"/metadata";
            }

    		headers.setContentType(new MediaType("application", "json+fhir"));
            requestEntity = new HttpEntity<>(headers);
             response = restTemplate.exchange(fhirMetaUrl, HttpMethod.GET, requestEntity, String.class);
            String capabilityStatementString = response.getBody();
        
            IParser parser = UtilitiesV1.myFhirContext.newJsonParser();
            CapabilityStatement capabilityStatement = (CapabilityStatement) parser.parseResource(capabilityStatementString);
            for (CapabilityStatementRestComponent rest : capabilityStatement.getRest()) {
                CapabilityStatementRestSecurityComponent security = rest.getSecurity();
                if (security != null && !security.isEmpty()) {
                    Extension tokenExtension = security.getExtensionByUrl("token");
                    if (tokenExtension != null && !tokenExtension.isEmpty()) {
                        UriType value = (UriType) tokenExtension.getValue();
                        if (value != null && !value.isEmpty()) {
                            return value.getValue();
                        }
                    }
                }
            }
            
            retToken = null;
        }

        return retToken;
    }
}
