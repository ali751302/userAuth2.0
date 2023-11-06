package com.example.userauth2_0.repository;

import com.example.userauth2_0.model.UserModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<UserModel,Long>{

        Optional<UserModel> findByUsername(String username);
        Optional<UserModel> findByEmail(String email);

}
