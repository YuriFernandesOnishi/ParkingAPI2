package com.example.estacionamento.Repository;

import com.example.estacionamento.Entity.Veiculos;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface VeiculosRepository extends JpaRepository<Veiculos, Integer> {
    List<Veiculos> findByPlaca(String placa);

    @Query("SELECT v FROM Veiculos v WHERE dataSaida IS NULL")
    List<Veiculos> findByDataEqualNull();
}
