// Pacote da configuração de segurança
package com.example.estacionamento.Security;

// Importações necessárias
import com.example.estacionamento.Entity.Usuario;
import com.example.estacionamento.Repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;

// Define esta classe como uma classe de configuração do Spring
@Configuration

// Habilita as configurações de segurança da aplicação
@EnableWebSecurity

// Lombok: injeta automaticamente as dependências via construtor
@RequiredArgsConstructor
public class SecurityConfig {

    // Filtro JWT que será executado antes da autenticação
    private final JwtFilter jwtFilter;

    // Repositório de usuários (acesso ao banco de dados)
    private final UsuarioRepository usuarioRepository;

    // Bean responsável por codificar (e comparar) senhas com BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Bean que carrega os dados do usuário com base no e-mail (usado pelo Spring Security)
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            // Busca o usuário no banco de dados
            Usuario user = usuarioRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            // Retorna um objeto User do Spring Security com email, senha e lista de roles vazia
            return new User(user.getEmail(), user.getSenha(), new ArrayList<>());
        };
    }

    // Define o provedor de autenticação que usa o userDetailsService e o codificador de senha
    @Bean
    public DaoAuthenticationProvider authenticationProvider(PasswordEncoder encoder,
                                                            UserDetailsService uds) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(uds); // serviço para buscar usuário
        provider.setPasswordEncoder(encoder); // codificador de senhas
        return provider;
    }

    // Define o AuthenticationManager padrão (Spring Security 6+)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // Define a cadeia de filtros de segurança e as configurações HTTP
    @Bean
    public SecurityFilterChain filterChain(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http
                // Desabilita CSRF pois a API é stateless (sem sessão)
                .csrf(csrf -> csrf.disable())

                // Define as rotas públicas e protegidas
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/api/veiculos/entrada").permitAll()
                        .requestMatchers("/api/veiculos/saida/**").permitAll()// Permite acesso sem autenticação às rotas de login/cadastro
                        .anyRequest().authenticated() // Qualquer outra rota exige autenticação
                )

                // Define que a aplicação não usa sessões (stateless, ideal para JWT)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Define o provedor de autenticação customizado
                .authenticationProvider(authenticationProvider(passwordEncoder(), userDetailsService()))

                // Adiciona o filtro JWT antes do filtro padrão de autenticação por usuário/senha
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // Constrói e retorna a configuração final
        return http.build();
    }
}
