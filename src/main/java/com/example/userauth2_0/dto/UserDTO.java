package com.example.userauth2_0.dto;

import com.example.userauth2_0.model.Authority;
import com.example.userauth2_0.model.UserModel;
import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Data
public class UserDTO {
    private Long id;
    private String username;
    private String firstname;
    private String lastname;
    private String email;
    boolean activated;
    Set<RolesDto> roles;

}
