package com.example.spriingSecurity1.config;

import com.example.spriingSecurity1.model.Customer;
import com.example.spriingSecurity1.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EasyBankDetailService implements UserDetailsService {

    private final CustomerRepository customerRepository;
    //Authentication 인터페이스는 사용자의 세부정보를 저장하고 검색하는 메서드를 포함
    //UserDetailsManager 인터페이스 사용자 세부 정보를 생성,업데이트,삭제 하는 메서드 제공
    //UserDetailsService 사용자별 데이터 로드
    //UserDetails 인터페이스 인증관련 겟유저네임,겟패스워드,기한 만료 등이며 이메일 인증등은 아니다
    //Authentication 인터페이스 사용자의 세부정보를 저장하고 검색하는 메서드를 포함

    //UserDetailsService 인터페이스의 사용자 지정 구현(이 부분이 유저세션 생성?)
    //UserDetailsService의 loadUserByUsername는 사용자 이름을 기준으로 사용자를 찾습니다
    //리턴값으로 세션에 저장
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer = customerRepository.findByEmail(username).orElseThrow(() -> new
                UsernameNotFoundException("User details not found for the user: " + username));
        List<GrantedAuthority> authorities = customer.getAuthorities().stream().map(authority -> new
                SimpleGrantedAuthority(authority.getName())).collect(Collectors.toList());
        return new User(customer.getEmail(), customer.getPwd(), authorities);
    }
}
