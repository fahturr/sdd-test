package com.sdd.fitness.controller;

import com.sdd.fitness.constant.Scheme;
import com.sdd.fitness.dto.BaseResponse;
import com.sdd.fitness.dto.response.MemberGetProfileResponse;
import com.sdd.fitness.service.MemberService;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@Tag(name = "Member Services")
public class MemberController {

    private final MemberService memberService;

    public MemberController(MemberService memberService) {
        this.memberService = memberService;
    }

    @GetMapping("/v1/member/profile")
    @SecurityRequirement(name = Scheme.AUTHORIZATION)
    public ResponseEntity<Object> getProfile(
            @Parameter(hidden = true) @RequestHeader(HttpHeaders.AUTHORIZATION) String bearer
    ) {
        BaseResponse<MemberGetProfileResponse> response = memberService.getProfile(bearer);

        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

}
