package com.sharmachait.security;

import lombok.Data;

import java.util.List;

@Data

public class LoginResponse {
    private String jwtToken;
    private String username;
    private List<String> roles;
    public LoginResponse(String jwtToken, String username, List<String> roles) {
        this.jwtToken = jwtToken;
        this.username = username;
        this.roles = roles;
    }
}
