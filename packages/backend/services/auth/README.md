# Authentication Service

## Environment
SALT_ROUND=10
HASH_SECRET=H3GmHGm7eeTFjIBVg2DJz7HM5uin2uYu
GLOBAL_PEPPER_KEY=I0K7n8o8w5P6e5p6p6e6r0I3s0G0r9e1a0t
JWT_PUBLIC_KEY_PATH=
JWT_PRIVATE_KEY_PATH=

## Internal Services
- User Service  (`user.service.ts`)
- Authentication Service (`auth.service.ts`)

## Example
Create User
```
call auth-user.createUser '{"usrNm": "lucduong", "usrEml": "luc@ltv.vn", "usrPwd": "123789"}'
```

Login
```
call auth-user.login '{"username": "lucduong", "password": "123789"}'
```

## Unit Test
### Create User
- Create Valid User
- Existed username
- Existed Email
- Without params
- Password HASHED

### Login
- Login valid user
- Invalid username or password
