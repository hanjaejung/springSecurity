package com.example.spriingSecurity1.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class EasyBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    private final EasyBankDetailService easyBankDetailService;
    private final PasswordEncoder passwordEncoder;

    //자체인증을 위한 Provider
    //로그인시 ProviderManager가 supports메소드 호출
    //그 다음 authenticate메소드 호출
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        UserDetails userDetails = easyBankDetailService.loadUserByUsername(username);

        if(passwordEncoder.matches(pwd, userDetails.getPassword())){
            return new UsernamePasswordAuthenticationToken(username,pwd,userDetails.getAuthorities());
        }else {
            throw new BadCredentialsException("Invalid password!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
