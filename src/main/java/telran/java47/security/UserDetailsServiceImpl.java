package telran.java47.security;

import java.time.LocalDate;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    final UserAccountRepository userAccountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = userAccountRepository.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        String[] roles = userAccount.getRoles()
                .stream()
                .map(r -> "ROLE_" + r)
				.toArray(String[]::new);
		LocalDate expDate = userAccount.getPasswordExpire();
        

       
        return new CustomUser(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles), expDate);
    }


}
