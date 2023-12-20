package com.sdd.fitness.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthRefreshTokenResponse {

    private String token;

}
