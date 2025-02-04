import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { stat } from 'fs';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger("AuthService");

    constructor(private readonly jwtService: JwtService) {
        super();
    }

    async signJWT(payload: JwtPayload) {
        return await this.jwtService.sign(payload);
    }
    onModuleInit() {
        this.$connect();
        this.logger.log("MongoDB connected");
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        try {
            const { name, email, password } = registerUserDto;
            const user = await this.user.findUnique({
                where: { email }
            });
            if (user) {
                throw new RpcException({
                    statusCode: HttpStatus.BAD_REQUEST,
                    error: "BAD_REQUEST",
                    message: `El email ya existe: ${user.email}`
                });
            }
            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password: bcrypt.hashSync(password, 10)
                }
            });
            const { password: ___, ...rest } = newUser;

            return { rest, token: await this.signJWT(rest) }
        } catch (error) {
            if (error instanceof RpcException) {
                throw error;
            }
            throw new RpcException({
                statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                error: "INTERNAL_SERVER_ERROR",
                message: error?.message || "Ocurrió un error inesperado"
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        try {
            const { email, password } = loginUserDto;
            const user = await this.user.findUnique({
                where: { email, }
            });
            if (!user) {
                throw new RpcException({
                    statusCode: HttpStatus.NOT_FOUND,
                    error: "NOT_FOUND",
                    message: `El email/contraseña son erroneos`
                });
            }
            const isPasswordValid = bcrypt.compareSync(password, user.password);
            if (!isPasswordValid) {
                throw new RpcException({
                    statusCode: HttpStatus.UNAUTHORIZED,
                    error: "UNAUTHORIZED",
                    message: `La contraseña no es correcta`
                });
            }
            const { password: ___, ...rest } = user;

            return { rest, token: await this.signJWT(rest) }
        } catch (error) {
            if (error instanceof RpcException) {
                throw error;
            }

            throw new RpcException({
                statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                error: "INTERNAL_SERVER_ERROR",
                message: error?.message || "Ocurrió un error inesperado"
            });
        }
    }

    async veritfyToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = await this.jwtService.verify(token, {
                secret: envs.JWT_SECRET
            });
            return {
                user,
                token: await this.signJWT(user)
            }
        } catch (error) {
            if (error instanceof RpcException) {
                throw error;
            }

            throw new RpcException({
                statusCode: HttpStatus.UNAUTHORIZED,
                error: "UNAUTHORIZED",
                message: "Token no valido"
            });
        }
    }
}
