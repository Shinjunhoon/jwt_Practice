package com.example.jwt_practice.login.dto;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Setter
@Getter
public class loginRequestDto {

    String username;
    String password;
}
