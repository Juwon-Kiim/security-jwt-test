package com.example.SpringJWT.service;

import com.example.SpringJWT.dto.JoinDto;
import com.example.SpringJWT.entity.UserEntity;
import com.example.SpringJWT.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void join(JoinDto joinDto){
        boolean isExist = userRepository.existsByUsername(joinDto.getUsername());
        if(isExist){
            System.out.println("이미 존재하는 회원입니다.");
            return;
        }
        UserEntity user = new UserEntity();
        user.setUsername(joinDto.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        user.setRole("ROLE_USER");

        userRepository.save(user);
    }
}
