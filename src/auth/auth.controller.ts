import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginUserDto, RegisterUserDto } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDto: RegisterUserDto) {
    // return registerUserDto;
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern('auth.login.user')
  LoginUser(@Payload() loginUserDto: LoginUserDto) {
    return loginUserDto;
    // return this.authService.registerUser(data);
  }

  @MessagePattern('auth.verify.token.user')
  verifyTokenUser() {
    return 'verifyTokenUsersss';
    // return this.authService.registerUser(data);
  }
}
