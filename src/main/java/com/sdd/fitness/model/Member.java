package com.sdd.fitness.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity(name = "member")
@Table
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "name")
    private String name;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "password")
    private String password;

    @Column(name = "card_number")
    private String cardNumber;

    @Column(name = "card_owner")
    private String cardOwner;

    @Column(name = "card_cvv")
    private String cardCvv;

    @Column(name = "card_expired_date")
    private String cardExpiredDate;

    @Column(name = "is_validate")
    private Boolean isValidate;

    public enum Status {
        ALREADY_REGISTER("Already Register"),
        NOT_REGISTER("Hasn't Been Register"),
        NOT_VALIDATE("Not Yet Validate");

        private final String value;

        Status(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

    }

}
