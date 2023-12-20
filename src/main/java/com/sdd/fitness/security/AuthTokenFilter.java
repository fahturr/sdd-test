package com.sdd.fitness.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sdd.fitness.constant.Message;
import com.sdd.fitness.dto.BaseResponse;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    private final UserDetailService userDetailService;

    public AuthTokenFilter(JwtUtil jwtUtil, UserDetailService userDetailService) {
        this.jwtUtil = jwtUtil;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws IOException {
        try {
            String token = jwtUtil.getBearerFromHeader(request);
            boolean isTokenValid = jwtUtil.validateToken(token);

            if (token != null & isTokenValid) {
                String email = jwtUtil.getEmailFromToken(token);

                UserDetails userDetail = userDetailService.loadUserByUsername(email);
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetail, null, userDetail.getAuthorities());

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            handleExpiredJwtException(response);
        } catch (Exception e) {
            handleExpiredDefaultException(response);
        }
    }

    private void handleExpiredJwtException(HttpServletResponse response) throws IOException {
        handleExeception(response, HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_EXPIRED);
    }

    private void handleExpiredDefaultException(HttpServletResponse response) throws IOException {
        handleExeception(response, HttpStatus.INTERNAL_SERVER_ERROR, Message.INTERNAL_SERVER_ERROR);
    }

    private void handleExeception(HttpServletResponse response, HttpStatusCode status, Message message) throws IOException {
        final ObjectMapper mapper = new ObjectMapper();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());

        BaseResponse<Object> body = BaseResponse.builder()
                .status(status)
                .message(message)
                .build();

        mapper.writeValue(response.getOutputStream(), body);
    }

}
