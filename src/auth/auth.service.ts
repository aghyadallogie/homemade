import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from 'src/users/users.service';

export type AuthInput = {
    email: string;
    password: string;
};

type SignInData = {
    id: string;
    email: string;
};

type AuthResult = {
    id: string;
    email: string;
    token: string;
}

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) { }

    // validate user credentials, if valid return user data for token payload
    async validateUser(input: AuthInput): Promise<SignInData | null> {
        const user = await this.usersService.findByEmail(input.email);
        if (!user || !user.password) return null;

        const isMatch = await bcrypt.compare(input.password, user.password);
        if (!isMatch) return null;

        return {
            id: user.id,
            email: user.email,
        };
    }

    // authenticate user and return signed JWT token, or throw UnauthorizedException
    async authenticate(input: AuthInput): Promise<AuthResult | null> {
        const validUser = await this.validateUser(input);

        if (!validUser) {
            throw new UnauthorizedException('Invalid credentials');
        }

        return this.signIn(validUser);
    }

    // sign and return JWT token for given user data, without validating credentials
    async signIn(user: SignInData): Promise<AuthResult> {
        const tokenPayload = {
            sub: user.id,
            email: user.email,
        };

        const accessToken = await this.jwtService.signAsync(tokenPayload);

        return {
            id: user.id,
            email: user.email,
            token: accessToken,
        };
    }

    /**
     * Register a new user:
     * - validates uniqueness by email
     * - hashes password
     * - creates user
     * - returns access token
     */
    async register(input: { email: string; username: string; password: string }) {
        const existing = await this.usersService.findByEmail(input.email);
        if (existing) {
            throw new BadRequestException('Email already in use');
        }

        const hashed = await bcrypt.hash(input.password, 10);
        const user = await this.usersService.create({
            email: input.email,
            username: input.username,
            password: hashed,
        });

        const payload = { username: user.username, sub: user.id };
        return { accessToken: this.jwtService.sign(payload) };
    }
}

export class RegisterDto {
    email: string;
    username: string;
    password: string;
}

export class LoginDto {
    email: string;
    password: string;
}