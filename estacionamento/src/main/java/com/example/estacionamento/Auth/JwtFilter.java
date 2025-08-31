package com.example.estacionamento.Auth;

import com.example.estacionamento.Entity.Usuario;
import com.example.estacionamento.Repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UsuarioRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 1) aceitar preflight OPTIONS sem autenticação
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2) tratar contextPath + uri para garantir match correto
        String contextPath = request.getContextPath() == null ? "" : request.getContextPath();
        String uri = request.getRequestURI(); // ex: /app/auth/register ou /auth/register
        String path = uri.startsWith(contextPath) ? uri.substring(contextPath.length()) : uri;

        // 3) ignorar todas as rotas públicas sob /auth/*
        if (path != null && (path.equals("/auth") || path.startsWith("/auth/"))) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        // 4) tentar extrair token com tratamento de exceção
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                jwt = authHeader.substring(7);
                username = jwtUtil.extractUsername(jwt); // jwtUtil deve retornar null se inválido
            }
        } catch (Exception ex) {
            // token inválido/malformado: não autentica, deixa seguir (dps o Spring retornará 401 se rota exigir)
            username = null;
            jwt = null;
        }

        try {
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                Usuario user = userRepository.findByEmail(username).orElse(null);
                if (user != null) {
                    User springUser = new User(user.getEmail(), user.getSenha(), new ArrayList<>());
                    if (jwt != null && jwtUtil.validateToken(jwt, springUser)) {
                        UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(springUser, null, springUser.getAuthorities());
                        authToken.setDetails(new org.springframework.security.web.authentication.WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }
        } catch (Exception ex) {
            // falha ao buscar usuário / validar token -> não autentica (não interrompe a requisição)
        }

        filterChain.doFilter(request, response);
    }
}
