package com.example.userservice.jpa;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserEntity, Long> {

    UserEntity findByuserId(String userId);

    UserEntity findByEmail(String username);
}
