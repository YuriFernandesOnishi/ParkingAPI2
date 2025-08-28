package com.example.estacionamento.Auth;

import lombok.Data;

@Data
public class AuthRequest {
    private String email;
    private String senha;
}
