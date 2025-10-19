package com.spring.security.security.config;

import com.spring.security.security.utils.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//shërben për të konfiguruar rregullat e sigurisë
//Kjo klasë përcakton se:
//Cilat URL janë të hapura pa autentikim (si regjistrimi dhe login-i),
//Cilat kërkesa kërkojnë autentikim,
//Çfarë lloj autentikimi përdor aplikacioni (në këtë rast HTTP Basic Auth).
@Configuration
public class SecurityConfig {
    //@Bean është një anotim që përdoret për të krijuar një objekt (një instancë klase)
// dhe për ta futur në kontekstin e Spring-ut, në mënyrë që të përdoret më vonë
// nga pjesë të tjera të aplikacionit.
//Mendo sikur Spring është një fabrikë, dhe ti i thua:
//“O Spring, krijo këtë objekt për mua dhe mbaje gati kur më duhet!”
//Këtë ia thua me @Bean.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                //Ky seksion i thotë Spring Security:
                //“Këto janë rregullat e autorizimit për endpoint-et e mia.”
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/register", "/auth/login").permitAll()
                        .requestMatchers("/auth/me").hasAnyRole("CLIENT", "BANKER", "ADMIN") // ose çfarë roli ke
                        .requestMatchers("/accounts").hasRole("CLIENT")
                        .requestMatchers("/transactions/**").hasRole("CLIENT")
                        .anyRequest().authenticated()
                )

                //Mos krijo session për përdoruesit
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //Kur dikush provon të bëjë login ose të verifikohet, përdor këtë provider
                .authenticationProvider(authenticationProvider())
                //Fut JWT filtrin përpara filtrit të zakonshëm të login-it me fjalëkalim
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build(); // vetem 1 here!
    }

    @Autowired
    UserDetailsService userDetailsService;

    // objekti që merret me login-in: kontrollon nëse email-i dhe password-i janë të saktë.
    private AuthenticationProvider authenticationProvider() {
        //"DAO" do të thotë që ky provider përdor një databazë për të marrë përdoruesin
        //Data Access Object
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService); // injektohet më lart
        authProvider.setPasswordEncoder(passwordEncoder());     // metodë që kthen BCrypt
        return authProvider;
    }

    @Bean
    //PasswordEncoder është një interfejs
    // që përdoret për të enkriptuar dhe verifikuar fjalëkalime.
    public PasswordEncoder passwordEncoder() {
        //BCryptPasswordEncoder është një implementim i sigurt i PasswordEncoder që përdor algoritmin BCrypt për enkriptim.
        //BCrypt është një algoritëm i fortë “one-way hashing”, që do të thotë:
        //Fjalëkalimi nuk mund të kthehet mbrapsht në tekst origjinal.
        //Çdo herë që e enkripton të njëjtin fjalëkalim, del një hash ndryshe,
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    //3
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
}
