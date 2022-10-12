package com.study.jwt_vue.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name="user")
@Data
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @NotNull
    @Size(min = 3, max = 50)
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotNull
    @Size(min = 3, max = 200)
    private String password;

    @NotNull
    @Size(min = 3, max = 10)
    private String nickname;

    private String email;
    private String role;
    private String provider;
    private String providerId;
    private Timestamp loginDate;

    @CreationTimestamp
    private Timestamp createDate;

    public List<String> getRoleList() {
        if(this.role.length() > 0) {
            return Arrays.asList(this.role.split(","));
        }
        return new ArrayList<>();
    }

    @Builder
    public User(long id, String username, String password, String nickname, String email, String role, String provider, String providerId, Timestamp loginDate, Timestamp createDate) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.nickname = nickname;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.loginDate = loginDate;
        this.createDate = createDate;
    }

    public static User from(User user) {
        if(user == null) return null;

        return   User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .nickname(user.getNickname())
                .email(user.getEmail())
                .role("ROLE_USER")
                .provider(user.getProvider())
                .providerId(user.getProviderId())
                .build();
    }

}
