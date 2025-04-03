package com.example.spriingSecurity1.config;

import com.example.spriingSecurity1.ExceptionHandling.CustomAccessDeniedHandler;
import com.example.spriingSecurity1.ExceptionHandling.CustomBasicAuthenticationEntryPoint;
import com.example.spriingSecurity1.filter.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //로그인 순서
        //1. 클라이언트가 유저이름과 비밀번호 요청
        //2. 서버에서 유저이름과 비밀번호를 받고 인증이 성공하면 토큰을 클라이언트에 발급한다
        //3. 클라이언트 어플리케이션은 보안 api에 접근할때마다 동일한 토큰을 백엔드 서버로 보낸다 이토큰이 유효하다면 백엔드 서버는 적절한 성공응답을 제공
        /* http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());*/
        /*http.authorizeHttpRequests((requests) -> requests.anyRequest().denyAll());*/
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        //이제부터 사용자 로그인 시키기 위해 자격증명을 받아 HttpBasic 형식으로 백엔드 서버에 전송 이러한 시나리오에서 스프링 시큐리티는 jsessionId를 생성하지 않는다 스프링 시큐리티에서 명시적으로 요청위해 아래의 2줄 코드를 작성
        //jsessionId는 톰캣에서 생성하는 거였다
        //jsessionId는 쓰지 않으니 주석처리
        //http.securityContext(contextConfig->contextConfig.requireExplicitSave(false)) //jsessionId 세부정보나 로그인된 인증 세부정부를 SecurityContextHolder에 저장하지 않겠다는 것

        http.sessionManagement(sessionConfig->sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(corsConfig->corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setExposedHeaders(Arrays.asList("Authorization"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .csrf(csrfConfig->csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler) //csrf 공격 해결책 소스
                        .ignoringRequestMatchers("/contact","/register","/apiLogin") //csrf 보호를 무시한다는 뜻
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())) //토큰이 백그라운드에서 느리게 생성이 되어 토큰을 수동으로 읽는게 필요 filter 생성이 필요
                //withHttpOnlyFalse 이거는 자바스크립트 코드의 클라이언트 어플리케이션이 쿠키를 읽을수 있개 해준다
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class) //기본 인증 필터 실행이 완료된 후 실행
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
                .requiresChannel(rcc-> rcc.anyRequest().requiresInsecure()) //Only HTTP
                //.csrf(csrfConfig->csrfConfig.disable())
                //http get은 데이터를 읽기만 해서 csrf 보호를 강제하지 않는다
                //데이터 변경 api 같은 경우에 예)post,put,delete에 대해서는 csrf 강제 보호 될것이다
                .authorizeHttpRequests((requests) -> requests
                               /* .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT") //권한테이블에 따른 권한 부여
                        .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE","VIEWACCOUNT") //권한을 하나만 가지고 있더라도 다른 권한도 볼수 있어야 할떄 쓴다
                        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/user").authenticated()*/
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER","ADMIN")
                        .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                .requestMatchers("/notices","/contact","/error","/register", "/invalidSession","/apiLogin").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(hbc->hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())); //401 에러 재정의시 이런식으로 httpBasic 메소드 수정 필요
        //진짜 충격이다 http.httpBasic() 이거만 표시한것만 해도 http.httpBasic()을 enable했다는 뜻
        //http.httpBasic()을 enable 하면 BasicAuthenticationFilter을 사용할 수 있다
        //BasicAuthenticationFilter을 사용하면 BasicAuthenticationFilter가 이를 가로채 인증을 진행
        //Authentication header를 이용하여 Basic {token} 값을 전달하여 인증을 하는 방식
        //token 값은 username:password를 BASE64로 인코딩하여 전달되는 값을 Filter에서 decode하여 인증을 진행
        //난 처음에 /user api에 어떻게 Authenticaton을 입력으로 받지? 궁금했는데 그래서 프론트에서 Athentication을 넣어서 주나? 했는데
        //강의를 봐도 안 그런거 같았다
        //확인해보니 먼저 그걸 가로챈다고 했다 구글 검색하니 그게 BasicAuthenticationFilter 였다
        //그리고 위에 설정한 .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
        //이부분이 사실 BasicAuthenticationFilter에 doFilterInternal을 통해서 인증을 진행하며
        //BasicAuthenticationConverter에서 convert메소드를 거의 그대로 붙여넣은 부분이었다
        //그리고 UsernamePasswordAuthenticationToken에 username : password 이런식으로 저장되어
        //BasicAuthenticationFilter로 돌아와서, authenticationManager를 통해서 인증 과정을 수행
        //그다음 SecurityContextHolder에 인증된 Authentication 객체를 저장해서
        //위의 작업이 먼저 진행되어서 /user에 Authentication으로 전달이 가능해진거다
        //이제 이해된다 대박이다
        //그래서 /apiLogin으로 새로 작성된 걸 보면 api 테스트를 진행했을때
        //Authentication을 만들어야 하니 authenticationManager를 쓰는게 나오는 거였다
        //이상 로그인할때 어떻게 저절로 Authentication에 유저네임과 패스워드가 들어오는 거지에 대한 궁금증이 해결되었다
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

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder){
        EasyBankUsernamePwdAuthenticationProvider authenticationProvider =
                new EasyBankUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(false); //ProviderManager는 객체 내부의 비밀번호를 지우지 않겠다는 뜻
        return  providerManager;
    }
}
