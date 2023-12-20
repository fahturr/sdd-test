package com.sdd.fitness.controller;

import com.sdd.fitness.dto.BaseResponse;
import com.sdd.fitness.dto.request.AuthLoginRequest;
import com.sdd.fitness.dto.request.AuthRegisterRequest;
import com.sdd.fitness.dto.request.AuthResetPasswordRequest;
import com.sdd.fitness.dto.response.AuthCheckStatusResponse;
import com.sdd.fitness.dto.response.AuthLoginResponse;
import com.sdd.fitness.dto.response.AuthRefreshTokenResponse;
import com.sdd.fitness.dto.response.AuthRegisterResponse;
import com.sdd.fitness.dto.response.AuthSubmitResetPasswordResponse;
import com.sdd.fitness.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Auth Services")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/v1/auth/register")
    public ResponseEntity<Object> register(
            @RequestBody @Valid AuthRegisterRequest request
    ) {
        BaseResponse<AuthRegisterResponse> response = authService.register(request);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @GetMapping("/v1/auth/validate/{token}")
    public ResponseEntity<Object> validateEmail(
            @PathVariable String token
    ) {
        BaseResponse<Object> response = authService.validate(token);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @PostMapping("/v1/auth/login")
    public ResponseEntity<Object> register(
            @RequestBody @Valid AuthLoginRequest request
    ) {
        BaseResponse<AuthLoginResponse> response = authService.login(request);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @GetMapping("/v1/auth/validate-check/{email}")
    public ResponseEntity<Object> checkStatusValidation(
            @PathVariable String email
    ) {
        BaseResponse<AuthCheckStatusResponse> response = authService.checkStatus(email);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @GetMapping("/v1/auth/refresh-token")
    public ResponseEntity<Object> refreshToken(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String bearer
    ) {
        BaseResponse<AuthRefreshTokenResponse> response = authService.refreshToken(bearer);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @GetMapping("/v1/auth/reset-password/{email}")
    public ResponseEntity<Object> submitResetPassword(
            @PathVariable String email
    ) {
        BaseResponse<AuthSubmitResetPasswordResponse> response = authService.submitResetPassword(email);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

    @PostMapping("/v1/auth/reset-password/{token}")
    public ResponseEntity<Object> resetPassword(
            @RequestBody AuthResetPasswordRequest request
    ) {
        BaseResponse<Object> response = authService.resetPassword(request);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }


}
