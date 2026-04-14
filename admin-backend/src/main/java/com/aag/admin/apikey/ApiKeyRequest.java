package com.aag.admin.apikey;

import jakarta.validation.constraints.NotBlank;

public class ApiKeyRequest {

    @NotBlank
    private String name;

    @NotBlank
    private String owner;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
}
