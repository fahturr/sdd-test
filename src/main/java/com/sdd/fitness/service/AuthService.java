package com.sdd.fitness.service;

import com.sdd.fitness.constant.Message;
import com.sdd.fitness.dto.BaseResponse;
import com.sdd.fitness.dto.request.AuthLoginRequest;
import com.sdd.fitness.dto.request.AuthRegisterRequest;
import com.sdd.fitness.dto.request.AuthResetPasswordRequest;
import com.sdd.fitness.dto.response.AuthCheckStatusResponse;
import com.sdd.fitness.dto.response.AuthLoginResponse;
import com.sdd.fitness.dto.response.AuthRefreshTokenResponse;
import com.sdd.fitness.dto.response.AuthRegisterResponse;
import com.sdd.fitness.dto.response.AuthSubmitResetPasswordResponse;
import com.sdd.fitness.exception.ResponseStatusException;
import com.sdd.fitness.model.Member;
import com.sdd.fitness.repository.MemberRepository;
import com.sdd.fitness.security.EncryptUtil;
import com.sdd.fitness.security.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final MemberRepository memberRepository;
    private final EncryptUtil encryptUtil;
    private final PasswordEncoder encoder;
    private final JwtUtil jwt;

    @Value("${com.sdd.fitness.validation-url}")
    private String validationUrl;

    @Value("${com.sdd.fitness.reset-password-url}")
    private String resetPasswordUrl;

    public AuthService(MemberRepository memberRepository, EncryptUtil encryptUtil, PasswordEncoder encoder, JwtUtil jwt) {
        this.memberRepository = memberRepository;
        this.encryptUtil = encryptUtil;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    public BaseResponse<AuthRegisterResponse> register(AuthRegisterRequest request) {
        try {
            String cardNumber = encryptUtil.encrypt(request.getCardNumber());
            String cardOwner = encryptUtil.encrypt(request.getCardOwner());
            String cvv = encryptUtil.encrypt(request.getCardCvv());
            String cardExpiredDate = encryptUtil.encrypt(request.getCardExpiredDate());

            Optional<Member> memberCheck = memberRepository.findByEmail(request.getEmail());
            if (memberCheck.isPresent()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.MEMBER_EXIST);
            }

            Member member = Member.builder()
                    .name(request.getName())
                    .email(request.getEmail())
                    .phone(request.getPhone())
                    .password(encoder.encode(request.getPassword()))
                    .isValidate(false)
                    .cardNumber(cardNumber)
                    .cardCvv(cvv)
                    .cardOwner(cardOwner)
                    .cardExpiredDate(cardExpiredDate)
                    .build();

            memberRepository.save(member);

            String validationToken = jwt.generateTokenValidationOrTokenReset(request.getEmail());

            AuthRegisterResponse payload = AuthRegisterResponse.builder()
                    .validationLink(validationUrl + validationToken)
                    .build();

            return BaseResponse.<AuthRegisterResponse>builder()
                    .status(HttpStatus.CREATED)
                    .message(Message.AUTH_REGISTER_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.<AuthRegisterResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<AuthRegisterResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<Object> validate(String token) {
        try {
            boolean isTokenValid = jwt.validateToken(token);

            if (!isTokenValid) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_INVALID);
            }

            String email = jwt.getEmailFromToken(token);
            Optional<Member> member = memberRepository.findByEmail(email);

            Member memberUpdate = member.get();
            memberUpdate.setIsValidate(true);

            memberRepository.save(memberUpdate);

            return BaseResponse.builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_VALIDATE_SUCCESS)
                    .build();
        } catch (ExpiredJwtException e) {
            return BaseResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .message(Message.valueOf(HttpStatus.BAD_REQUEST.name()))
                    .additionalInfo(Message.JWT_TOKEN_EXPIRED.value())
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<AuthLoginResponse> login(AuthLoginRequest request) {
        try {
            Member member = memberRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, Message.MEMBER_NOT_FOUND));

            String rawPassword = request.getPassword();
            String hashedPassword = member.getPassword();

            if (!encoder.matches(rawPassword, hashedPassword)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.AUTH_LOGIN_WRONG_CREDENTIAL);
            }

            if (!member.getIsValidate()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.AUTH_LOGIN_NOT_ACTIVATED);
            }

            String authToken = jwt.generateTokenAuth(member.getEmail());

            AuthLoginResponse payload = AuthLoginResponse.builder()
                    .token(authToken)
                    .build();

            return BaseResponse.<AuthLoginResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_LOGIN_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.<AuthLoginResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<AuthLoginResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<AuthCheckStatusResponse> checkStatus(String email) {
        try {
            Optional<Member> member = memberRepository.findByEmail(email);

            if (member.isEmpty()) {
                AuthCheckStatusResponse payload = AuthCheckStatusResponse.builder()
                        .status(Member.Status.NOT_REGISTER.value())
                        .build();

                return BaseResponse.<AuthCheckStatusResponse>builder()
                        .status(HttpStatus.OK)
                        .message(Message.AUTH_CHECK_STATUS_SUCCESS)
                        .payload(payload)
                        .build();
            }

            if (!member.get().getIsValidate()) {
                AuthCheckStatusResponse payload = AuthCheckStatusResponse.builder()
                        .status(Member.Status.NOT_VALIDATE.value())
                        .build();

                return BaseResponse.<AuthCheckStatusResponse>builder()
                        .status(HttpStatus.OK)
                        .message(Message.AUTH_VALIDATE_SUCCESS)
                        .payload(payload)
                        .build();
            }

            AuthCheckStatusResponse payload = AuthCheckStatusResponse.builder()
                    .status(Member.Status.ALREADY_REGISTER.value())
                    .build();

            return BaseResponse.<AuthCheckStatusResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_VALIDATE_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.<AuthCheckStatusResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<AuthCheckStatusResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<AuthRefreshTokenResponse> refreshToken(String bearer) {
        String newToken = "";

        try {
            String email = jwt.getEmailFromBearer(bearer);
            if (email == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_INVALID);
            }

            newToken = jwt.generateTokenAuth(email);
            jwt.validateToken(bearer);

            AuthRefreshTokenResponse payload = AuthRefreshTokenResponse.builder()
                    .token(newToken)
                    .build();

            return BaseResponse.<AuthRefreshTokenResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_REFRESH_TOKEN_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ExpiredJwtException e) {
            AuthRefreshTokenResponse payload = AuthRefreshTokenResponse.builder()
                    .token(newToken)
                    .build();

            return BaseResponse.<AuthRefreshTokenResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_REFRESH_TOKEN_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.<AuthRefreshTokenResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<AuthRefreshTokenResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<AuthSubmitResetPasswordResponse> submitResetPassword(String email) {
        try {
            memberRepository.findByEmail(email)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, Message.MEMBER_NOT_FOUND));

            String tokenReset = jwt.generateTokenValidationOrTokenReset(email);
            String url = resetPasswordUrl + tokenReset;

            AuthSubmitResetPasswordResponse payload = AuthSubmitResetPasswordResponse.builder()
                    .resetPasswordUrl(url)
                    .build();

            return BaseResponse.<AuthSubmitResetPasswordResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_SUBMIT_RESET_PASSWORD_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.<AuthSubmitResetPasswordResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<AuthSubmitResetPasswordResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

    public BaseResponse<Object> resetPassword(AuthResetPasswordRequest request) {
        try {
            if (!request.getNewPassword().equals(request.getNewPasswordConfirm())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.AUTH_RESET_PASSWORD_NOT_MATCH);
            }

            boolean isTokenValid = jwt.validateToken(request.getToken());

            if (!isTokenValid) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_INVALID);
            }

            String email = jwt.getEmailFromToken(request.getToken());
            Member member = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, Message.MEMBER_NOT_FOUND));

            member.setPassword(encoder.encode(request.getNewPassword()));
            memberRepository.save(member);

            return BaseResponse.builder()
                    .status(HttpStatus.OK)
                    .message(Message.AUTH_RESET_PASSWORD_SUCCESS)
                    .build();
        } catch (ExpiredJwtException e) {
            return BaseResponse.builder()
                    .status(HttpStatus.BAD_REQUEST)
                    .message(Message.valueOf(HttpStatus.BAD_REQUEST.name()))
                    .additionalInfo(Message.JWT_TOKEN_EXPIRED.value())
                    .build();
        } catch (ResponseStatusException e) {
            return BaseResponse.builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

}
