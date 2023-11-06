package com.example.userauth2_0.service;

import com.example.userauth2_0.dto.UserDTO;
import com.example.userauth2_0.model.UserModel;
import com.example.userauth2_0.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    ModelMapper modelMapper;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserModel> user = userRepository.findByUsername(username);
        if(user.isEmpty()){
            throw new UsernameNotFoundException("User not found");
        }
        return new User(username, user.get().getPassword(),user.get().isEnabled(),true,true,true, user.get().getAuthorities());
    }


    public UserModel saveUser(UserModel user) {
        String password = user.getPassword();
        String encodedPassword = passwordEncoder.encode(password);
        user.setPassword(encodedPassword);

        return userRepository.save(user);
    }

    public UserDTO getUserById(Long id){
        Optional<UserModel> user = userRepository.findById(id);
        UserDTO userDTO;

        if(user.isPresent()){
            userDTO = modelMapper.map(user.get(),UserDTO.class);
            return userDTO;
        }else{
            throw new UsernameNotFoundException("User with id '"+ id +"' not found.");
        }
    }
}
