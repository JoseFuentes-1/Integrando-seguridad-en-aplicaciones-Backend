package com.minimarket.security.config;

import com.minimarket.security.filter.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                // Productos: todos los autenticados pueden ver, solo ADMIN y EMPLEADO pueden modificar
                .requestMatchers(HttpMethod.GET, "/api/productos/**").hasAnyRole("ADMIN", "EMPLEADO", "CLIENTE")
                .requestMatchers(HttpMethod.POST, "/api/productos/**").hasAnyRole("ADMIN", "EMPLEADO")
                .requestMatchers(HttpMethod.PUT, "/api/productos/**").hasAnyRole("ADMIN", "EMPLEADO")
                .requestMatchers(HttpMethod.DELETE, "/api/productos/**").hasRole("ADMIN")
                // Usuarios: solo ADMIN
                .requestMatchers("/api/usuarios/**").hasRole("ADMIN")
                // Inventario: ADMIN y EMPLEADO
                .requestMatchers("/api/inventario/**").hasAnyRole("ADMIN", "EMPLEADO")
                // Categorias: todos autenticados pueden ver, ADMIN puede modificar
                .requestMatchers(HttpMethod.GET, "/api/categorias/**").hasAnyRole("ADMIN", "EMPLEADO", "CLIENTE")
                .requestMatchers("/api/categorias/**").hasRole("ADMIN")
                // Ventas: ADMIN y EMPLEADO
                .requestMatchers("/api/ventas/**").hasAnyRole("ADMIN", "EMPLEADO")
                .requestMatchers("/api/detalle-ventas/**").hasAnyRole("ADMIN", "EMPLEADO")
                // Carrito: CLIENTE, EMPLEADO y ADMIN
                .requestMatchers("/api/carrito/**").hasAnyRole("ADMIN", "EMPLEADO", "CLIENTE")
                // Cualquier otra ruta requiere autenticacion
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
