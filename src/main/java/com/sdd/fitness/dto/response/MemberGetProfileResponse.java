package com.sdd.fitness.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MemberGetProfileResponse {

    private String name;

    private String email;

    private String phone;

    private String cardNumber;

    private String cardOwner;

    private String cardCvv;

    private String cardExpiredDate;

}
