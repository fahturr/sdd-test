package com.sdd.fitness.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthResetPasswordRequest {

    private String token;

    @NotBlank
    private String newPassword;

    @NotBlank
    private String newPasswordConfirm;

}
