import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';

type AuthInput = {
    username: string;
    password: string;
};

type SignInData = {
    userId: string;
    username: string;
};

type AuthResult = {
    userId: string;
    username: string;
    token: string;
}

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) { }

    async validateUser(input: AuthInput): Promise<SignInData | null> {
        // const user = await this.usersService.findByUsername(input.username);
        const users = await this.usersService.findAll();
        console.log('xxxxxxxxxxxxxxxxx', users);
        // if (user && user.password === input.password) {
        //     return {
        //         userId: user.userId,
        //         username: user.username,
        //     };
        // }
        return null;
    }

    async authenticate(input: AuthInput): Promise<AuthResult | null> {
        const validUser = await this.validateUser(input);

        if (!validUser) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return this.signIn(validUser);
    }

    async signIn(user: SignInData): Promise<AuthResult> {
        const tokenPayload = {
            sub: user.userId,
            username: user.username
        };

        const accessToken = await this.jwtService.signAsync(tokenPayload);

        return {
            userId: user.userId,
            username: user.username,
            token: accessToken,
        };
    }
}
