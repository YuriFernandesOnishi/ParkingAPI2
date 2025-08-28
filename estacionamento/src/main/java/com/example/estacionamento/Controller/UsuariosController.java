package com.example.estacionamento.Controller;

import com.example.estacionamento.Entity.Usuario;
import com.example.estacionamento.Repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuariosController {

        @Autowired
        public UsuarioRepository usuarioRepository;
        @GetMapping
        public List<Usuario> listarUsuario() {
            return usuarioRepository.findAll();
        }

        @GetMapping("/{id}")
        public Usuario pesquisarUsuario(@PathVariable int id) {
            return usuarioRepository.findById(id).orElse(null);
        }

    @PostMapping
    public ResponseEntity<String> criarUsuario(@RequestBody Usuario usuario) {
        usuarioRepository.save(usuario);
        return ResponseEntity.ok("Usuário criado com sucesso.");
    }
}



