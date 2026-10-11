package nl.fontys.securedesk.config;

import nl.fontys.securedesk.auth.RecentAuthenticationInterceptor;
import nl.fontys.securedesk.auth.Sleeper;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final RecentAuthenticationInterceptor recentAuthentication;

    public WebConfig(RecentAuthenticationInterceptor recentAuthentication) {
        this.recentAuthentication = recentAuthentication;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(recentAuthentication).addPathPatterns("/api/**");
    }

    /** First of all filters, so even a request Spring Security refuses has a correlation id. */
    @Bean
    public FilterRegistrationBean<CorrelationIdFilter> correlationIdFilter() {
        FilterRegistrationBean<CorrelationIdFilter> registration = new FilterRegistrationBean<>(new CorrelationIdFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    public Sleeper sleeper() {
        return Sleeper.threadSleep();
    }
}
