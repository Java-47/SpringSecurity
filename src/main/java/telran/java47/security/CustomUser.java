package telran.java47.security;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.Collection;

@Setter
@Getter
public class CustomUser extends User {
    /**
	 * 
	 */
	private static final long serialVersionUID = 6899177625858775669L;
	private LocalDate expDate;

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, LocalDate expDate) {
        super(username, password, authorities);
        this.expDate = expDate;
    }

}