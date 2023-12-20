package com.sdd.fitness.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthRegisterRequest {

    @NotBlank
    private String name;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    @NotBlank
    private String phone;

    @NotBlank
    private String cardNumber;

    @NotBlank
    private String cardCvv;

    @NotBlank
    private String cardExpiredDate;

    @NotBlank
    private String cardOwner;

}
