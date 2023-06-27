package com.magadiflo.jwt.template.project.app.business.repositories;

import com.magadiflo.jwt.template.project.app.business.entities.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
