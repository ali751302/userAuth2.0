package com.example.userauth2_0.webcontroller;

import com.example.userauth2_0.dto.LoginDTO;
import com.example.userauth2_0.dto.SignupDTO;
import com.example.userauth2_0.model.Authority;
import com.example.userauth2_0.model.UserModel;
import com.example.userauth2_0.security.TokenGenerator;
import com.example.userauth2_0.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.AuthenticationException;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
//    @Autowired
//    UserDetailsManager userDetailsManager;


    @Autowired
    TokenGenerator tokenGenerator;

    @Autowired
    DaoAuthenticationProvider daoAuthenticationProvider;

    @Autowired
    ModelMapper modelMapper;

    @Autowired
    UserService userService;

    @Autowired
    @Qualifier("jwtAuthenticationProvider")
    JwtAuthenticationProvider refreshTokenAuthProvider;

    @Autowired
    @Qualifier("jwtAccessTokenAuthProvider")
    JwtAuthenticationProvider jwtAuthenticationProvider;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody SignupDTO signupDTO){
        UserModel userModel = modelMapper.map(signupDTO,UserModel.class);
        Set<Authority> authoritiesSet = new HashSet<>();
        authoritiesSet.add(new Authority(3L,"USER"));

        userModel.setRoles(authoritiesSet);
        userModel = userService.saveUser(userModel);

        User user = new User(userModel.getUsername(), userModel.getPassword(),userModel.getAuthorities());

        Authentication authentication = UsernamePasswordAuthenticationToken
                .authenticated(user,signupDTO.getPassword(), userModel.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO){

        UserDetails user = userService.loadUserByUsername(loginDTO.getUsername());
        Authentication authentication= daoAuthenticationProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDTO.getUsername(), loginDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
    }



//    @PostMapping("/token")
//    public ResponseEntity Token(@RequestBody TokenDTO tokenDTO){
//        Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(tokenDTO.getRefreshToken()));
//        return ResponseEntity.ok(tokenGenerator.createToken(authentication));
//    }

    @PostMapping("/verifyUser")
    public ResponseEntity<?> verifyUser(@RequestHeader("Authorization") String token){
        BearerTokenAuthenticationToken bearerToken = new BearerTokenAuthenticationToken(token);
        Jwt jwt;
        try {
            Authentication authentication = jwtAuthenticationProvider.authenticate(bearerToken);
            jwt = (Jwt) authentication.getCredentials();
        }catch (AuthenticationException aExp){
            throw new RuntimeException("Token not found.");
        }
        return ResponseEntity.ok(jwt);
    }

}
