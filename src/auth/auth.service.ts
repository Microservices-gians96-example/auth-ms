import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { stat } from 'fs';
import { RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    private readonly logger = new Logger("AuthService");
    onModuleInit() {
        this.$connect();
        this.logger.log("MongoDB connected");
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        try {
            console.log(registerUserDto);
            
            const { name, email, password } = registerUserDto;
            const user = await this.user.findUnique({
                where: { email }
            });
            if (user) {
                throw new RpcException({
                    statusCode: 400,
                    error: "Email ya existe",
                    message: "El email ya existe"
                });
            }
            const newUser = await this.user.create({
                data: {
                    name,
                    email,
                    password
                }
            });
            return { newUser, token: "123456789" }
        } catch (error) {
            throw new RpcException({
                statusCode: 400,
                error: error.message
            });
        }
    }
}
