package com.example.estacionamento.Services;

import com.example.estacionamento.Auth.AuthRequest;
import com.example.estacionamento.Auth.JwtUtil;
import com.example.estacionamento.Entity.Usuario;
import com.example.estacionamento.Repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public void register(AuthRequest request) {
        userRepository.findByEmail(request.getEmail()).ifPresent(u -> {
            throw new RuntimeException("Usuário já existe");
        });

        Usuario user = new Usuario();
        user.setNome("Usuário"); // ajuste se quiser receber no request
        user.setEmail(request.getEmail());
        user.setSenha(passwordEncoder.encode(request.getSenha()));
        user.setAdmin(false);

        userRepository.save(user);
    }

    public String login(AuthRequest request) {
        // Autentica email/senha
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getSenha())
        );

        // Carrega o usuário e gera o token
        Usuario u = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        UserDetails userDetails = new User(u.getEmail(), u.getSenha(), new ArrayList<>());

        return jwtUtil.generateToken(userDetails);
    }
}
