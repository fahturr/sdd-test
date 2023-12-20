package com.sdd.fitness.dto.request;

import lombok.Data;

@Data
public class AuthLoginRequest {

    private String email;

    private String password;

}
