package com.cinzogoni.springsecurity_jwt.repository;

import com.cinzogoni.springsecurity_jwt.entities.Role;
import com.cinzogoni.springsecurity_jwt.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByRole(Role role);
}
