package com.example.spriingSecurity1.config;

import com.example.spriingSecurity1.ExceptionHandling.CustomAccessDeniedHandler;
import com.example.spriingSecurity1.ExceptionHandling.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
       /* http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());*/
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());*/
        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession").maximumSessions(3).maxSessionsPreventsLogin(true)) //세션 시간 지났을시 이동되는 페이지 따로 /invalidSession에 대한 페이지를 설정하면 그쪽으로 이동한다 설정하는 페이지가 없으면 /invalidSession에 대한 잘못된 세션으로 리디렌션 된다
                //동시 세션 부분 추가
                .requiresChannel(rcc-> rcc.anyRequest().requiresSecure()) //Only HTTPS
                .csrf(csrfConfig->csrfConfig.disable())
                //http get은 데이터를 읽기만 해서 csrf 보호를 강제하지 않는다
                //데이터 변경 api 같은 경우에 예)post,put,delete에 대해서는 csrf 강제 보호 될것이다
                .authorizeHttpRequests((requests) -> requests.requestMatchers("/myAccount","/myBalance","/myLoans","/myCards").authenticated()
                .requestMatchers("/notices","/contact","/error","/register").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(hbc->hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())); //401 에러 재정의시 이런식으로 httpBasic 메소드 수정 필요
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler())); // 403 에러는 전역적으로 설정해야 합니다
        return http.build();
    }

    /* 이 부분이 헷갈렸지만 드디어 정리 이부분은 UserDetails로 유저 생성 후
       스프링 부트 어플리케이션의 메모리내에 사용자를 정의하는것
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("testUser")
                .password("{noop}1111").authorities("read").build();
        UserDetails admin = User.withUsername("admin")
                .password("{bcrypt}$2a$12$qjQ9WlqkBOvJ1JC4RByGpuervyzYzO7ljilimw22J06TDXxc0tiL2").authorities("admin").build();

        return new InMemoryUserDetailsManager(user, admin); //userDetails 객체 전달,  어플리케이셔 메모리내에 사용자 세부내용 저장
        //여러명의 사용자 받아드릴수 있다
    }
    */

    /*
    JdbcUserDetailsManager는 UserDetailsService 인터페이스의 구현체로, JDBC를 사용하여 데이터베이스에서 사용자 세부 정보를 조회함으로써
     사용자 인증 및 권한 부여를 제공합니다
     즉 위의 주석은 데이터베이스 사용전 직접 스프링 부트에서 사용자를 생성해서
     스프링부트 메모리내에 생성한것이며
     이것은 드디어 데이터베이스에 저장되어 있던걸 조회하는 용도이다
     이 부분이 주석처리된 이유는 EasyBankSecurityDetailService클래스에
     UserDetailsService를 구현했기 때문이다 두번이상 등록하면 스프링 부트가 어떤
     걸 잡아야 할지 몰라 에러가 난다고 선생님이 말씀하셨다
     @Bean
     public UserDetailsService userDetailsService(DataSource dataSource){
         return new JdbcUserDetailsManager(dataSource);
     }
     */


    //createDelegatingPasswordEncoder를 사용하면 스프링 시큐리티에서 새로운
    //비밀번호가 등장하더라도 코드 변경을 할 필요가없다
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker(){
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
