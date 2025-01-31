import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @MessagePattern('auth-register-user')
  registerUser() {
    return 'registerUser';
    // return this.authService.registerUser(data);
  }

  LoginUser() {
    return 'LoginUser';
    // return this.authService.registerUser(data);
  }

  verifyTokenUser() {
    return 'verifyTokenUser';
    // return this.authService.registerUser(data);
  }
}
