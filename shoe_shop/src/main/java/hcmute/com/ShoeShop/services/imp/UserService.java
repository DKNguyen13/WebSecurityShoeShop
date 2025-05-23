package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService{
    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    public long count() {
        return userRepository.count();
    }

    public void delete(Users user) {
        userRepository.delete(user);
    }

    public List<Users> findAll() {
        return userRepository.findAll();
    }

    public Page<Users> findAll(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    public void saveUser(Users user) {
        user.setPass(passwordEncoder.encode(user.getPass()));
        userRepository.save(user);
    }

    public Users findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public List<Users> findByFullnameAndRole(String name, int roleid){
        return userRepository.findByRoleIdAndContainName(name, roleid);
    }

    public Users findUserByUserID(int userId){
        return userRepository.findUsersById(userId);
    }

    public void updateUser(Users user, String fullname, String address, String phone) {
        user.setFullname(fullname);
        user.setAddress(address);
        user.setPhone(phone);
        userRepository.save(user);
    }
}
