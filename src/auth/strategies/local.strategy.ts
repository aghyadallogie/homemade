import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private authService: AuthService) {
        // tell passport to read "email" from the request body as the identifier
        super({ usernameField: 'email' });
    }

    async validate(email: string, password: string) {
        const user = await this.authService.authenticate({ email, password });
        if (!user) {
            throw new UnauthorizedException();
        }
        return user;
    }
}