package com.example.userauth2_0.webcontroller;


import com.example.userauth2_0.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/{id}")
   public ResponseEntity<?> User(@PathVariable Long id){
        return ResponseEntity.ok(userService.getUserById(id));
    }

}
