import { Body, Controller, Get, HttpCode, HttpStatus, Post, Request, UseGuards } from "@nestjs/common";
import { AuthService, LoginDto, RegisterDto } from "./auth.service";
import { PassportJwtAuthGuard } from "./guards/passport-jwt.guard";
import { PassportLocalGuard } from "./guards/passport-local.guard";

/**
 * Authentication controller using Passport strategies.
 *
 * Endpoints:
 * - POST /auth/login -> authenticate with email/password (LocalStrategy) and return a JWT.
 * - GET  /auth/me    -> return authenticated user's info (requires Bearer JWT).
 */
@Controller('auth')
export class PassportAuthController {
    constructor(private authService: AuthService) { }

    /**
     * Authenticate user and return a signed JWT.
     * Guard: PassportLocalGuard (validates credentials and attaches user to request.user).
     *
     * @param request - Express request; authenticated user is available at request.user
     * @returns signed token payload from AuthService.signIn
     */
    @HttpCode(HttpStatus.OK)
    @Post('login')
    @UseGuards(PassportLocalGuard)
    login(@Body() input: LoginDto) {
        return this.authService.authenticate(input);
    }

    /**
     * Return the current authenticated user's public data.
     * Guard: PassportJwtAuthGuard (validates Bearer token and populates request.user).
     *
     * @param request - Express request with user populated by JwtStrategy
     * @returns user object attached to the request
     */
    @Get('me')
    @UseGuards(PassportJwtAuthGuard)
    getUserInfo(@Request() request) {
        return request.user;
    }

    /**
     * Register a new user and return authentication result.
     *
     * Validates input, creates user via AuthService, and returns token on success.
     *
     * @param input - RegisterDto containing email, username and password
     * @returns created user auth result (token or error)
     */
    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() input: RegisterDto) {
        return this.authService.register(input);
    }
}
