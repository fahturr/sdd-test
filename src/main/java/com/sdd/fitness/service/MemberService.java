package com.sdd.fitness.service;

import com.sdd.fitness.constant.Message;
import com.sdd.fitness.dto.BaseResponse;
import com.sdd.fitness.dto.response.MemberGetProfileResponse;
import com.sdd.fitness.exception.ResponseStatusException;
import com.sdd.fitness.model.Member;
import com.sdd.fitness.repository.MemberRepository;
import com.sdd.fitness.security.EncryptUtil;
import com.sdd.fitness.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class MemberService {

    private final JwtUtil jwt;
    private final MemberRepository memberRepository;
    private final EncryptUtil encryptUtil;

    public MemberService(JwtUtil jwt, MemberRepository memberRepository, EncryptUtil encryptUtil) {
        this.jwt = jwt;
        this.memberRepository = memberRepository;
        this.encryptUtil = encryptUtil;
    }

    public BaseResponse<MemberGetProfileResponse> getProfile(String bearer) {
        try {
            String email = jwt.getEmailFromBearer(bearer);

            Member member = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, Message.MEMBER_NOT_FOUND));

            String cardNumber = encryptUtil.decrypt(member.getCardNumber());
            String cardCvv = encryptUtil.decrypt(member.getCardCvv());
            String cardOwner = encryptUtil.decrypt(member.getCardOwner());
            String cardExpiredDate = encryptUtil.decrypt(member.getCardExpiredDate());

            MemberGetProfileResponse payload = MemberGetProfileResponse.builder()
                    .name(member.getName())
                    .email(member.getEmail())
                    .phone(member.getPhone())
                    .cardNumber(cardNumber)
                    .cardCvv(cardCvv)
                    .cardOwner(cardOwner)
                    .cardExpiredDate(cardExpiredDate)
                    .build();

            return BaseResponse.<MemberGetProfileResponse>builder()
                    .status(HttpStatus.OK)
                    .message(Message.MEMBER_GET_PROFILE_SUCCESS)
                    .payload(payload)
                    .build();
        } catch (
                ResponseStatusException e) {
            return BaseResponse.<MemberGetProfileResponse>builder()
                    .status(e.getStatusCode())
                    .message(Message.valueOf(e.getReason()))
                    .additionalInfo(e.getEMessage().value())
                    .build();
        } catch (Exception e) {
            return BaseResponse.<MemberGetProfileResponse>builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .message(Message.INTERNAL_SERVER_ERROR)
                    .additionalInfo(e.getMessage())
                    .build();
        }
    }

}
