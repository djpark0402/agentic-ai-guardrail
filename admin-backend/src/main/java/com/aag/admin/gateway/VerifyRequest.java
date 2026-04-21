package com.aag.admin.gateway;

import jakarta.validation.constraints.NotBlank;

public class VerifyRequest {

    @NotBlank private String apiKey;
    @NotBlank private String timestamp;
    @NotBlank private String nonce;
    @NotBlank private String bodyHash;
    @NotBlank private String signature;

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }
    public String getBodyHash() { return bodyHash; }
    public void setBodyHash(String bodyHash) { this.bodyHash = bodyHash; }
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}
