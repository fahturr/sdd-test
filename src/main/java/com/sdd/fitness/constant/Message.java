package com.sdd.fitness.constant;

public enum Message {

    MEMBER_EXIST("Member already registered"),
    MEMBER_NOT_FOUND("Member not found"),

    INTERNAL_SERVER_ERROR("Error server"),
    BAD_REQUEST("Bad Request"),
    UNAUTHORIZED("Unauthorized"),
    FORBIDDEN("Forbidden"),
    UNPROCESSABLE_ENTITY("Unprocessable Entity"),
    AUTHORIZATION_HEADER_EMPTY("Empty Authorization Header"),
    VALIDATION_ERROR("Validation Error"),

    JWT_TOKEN_EXPIRED("Token already expired"),
    JWT_TOKEN_INVALID("Token invaldi"),


    AUTH_REGISTER_SUCCESS("Success register membership"),
    AUTH_VALIDATE_SUCCESS("Success validating member"),
    AUTH_CHECK_STATUS_SUCCESS("Success check status"),
    AUTH_LOGIN_SUCCESS("Login Success"),
    AUTH_LOGIN_WRONG_CREDENTIAL("Wrong Credential"),
    AUTH_LOGIN_NOT_ACTIVATED("Account Not Yet Validated"),
    AUTH_REFRESH_TOKEN_SUCCESS("Refresh Token Success"),
    AUTH_SUBMIT_RESET_PASSWORD_SUCCESS("Reset Password Has Requested"),
    AUTH_RESET_PASSWORD_SUCCESS("Reset Password Success"),
    AUTH_RESET_PASSWORD_NOT_MATCH("Confirmation Password is Not Same"),

    MEMBER_GET_PROFILE_SUCCESS("Success Get Member Profile")
    ;

    private final String value;

    Message(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

}
