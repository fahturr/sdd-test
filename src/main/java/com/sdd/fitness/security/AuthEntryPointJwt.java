package com.sdd.fitness.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sdd.fitness.constant.Message;
import com.sdd.fitness.dto.BaseResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        BaseResponse<Object> body = BaseResponse.builder()
                .status(HttpStatus.UNAUTHORIZED)
                .message(Message.UNAUTHORIZED)
                .build();

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization == null) {
            body = BaseResponse.builder()
                    .status(HttpStatus.UNAUTHORIZED)
                    .message(Message.AUTHORIZATION_HEADER_EMPTY)
                    .build();
        }

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}
