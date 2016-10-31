package my.first.shrio.realms;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyShrioRealm extends AuthorizingRealm {
	// 授权时 shiro 会回调的方法. 
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {
		// TODO Auto-generated method stub
		return null;
	}
	// 认证时 shiro 会回调的方法
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		
		//1. 把 AuthenticationToken 强转为 UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		
		//2. 从 UsernamePasswordToken 中获取 username
		String username = upToken.getUsername();
		
		//3. 利用 username 从数据库中获取对应的用户信息. 包括密码
		System.out.println("利用username["+username+"]从数据库中获取对应的用户信息");
		
		if("unknown".equals(username)){
			throw new UnknownAccountException("用户名不存在");
		}
		if("monster".equals(username)){
			throw new LockedAccountException("用户名被锁定");
		}
		
		//4. 把用户信息封装为一个 SimpleAuthenticationInfo 对象, 并返回
		//认证的实体信息. 可以是一个 User 对象. 也可以是 username .
		Object principal = username;
		
		//从数据库中取得的密码
		String credentials = null;
		
		//盐值加密的 盐
		ByteSource salt = ByteSource.Util.bytes(username);
		
		if("user".equals(username)){
			credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		else if("admin".equals(username)) {
			credentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		}
		
		//当前 Realm 的 name 属性值. 可以直接调用父类的 getName() 方法来获取
		String realmName = getName();
		
		//当前 Realm 的 name 属性值. 可以直接调用父类的 getName() 方法来获取
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, salt, realmName);
		
		return info;
	}
	
	public static void main(String[] args) {
		
		String algorithmName = "MD5";
		
		String source = "123456";
		
		Object salt = ByteSource.Util.bytes("admin");
		
		int hashIterations = 1024;
		
		SimpleHash simpleHash = new SimpleHash(algorithmName, source, salt, hashIterations);
		
		System.out.println("simpleHash-->"+simpleHash);
		
	}
	
}
