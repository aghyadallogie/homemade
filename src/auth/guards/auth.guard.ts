import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";

@Injectable()
/**
 * Guard that validates a JWT from the Authorization header and attaches the
 * decoded user payload to request.user.
 *
 * Throws UnauthorizedException when the Authorization header is missing,
 * the Bearer token is missing, or token verification fails.
 */
export class AuthGuard implements CanActivate {
    /**
     * Create an AuthGuard.
     * @param jwtService - JwtService used to verify JWT tokens.
     */
    constructor(private jwtService: JwtService) { }

    /**
     * Extracts the Bearer token from the Authorization header, verifies it using
     * JwtService.verifyAsync and attaches a user object to the request:
     *   { userId: payload.sub, username: payload.username }
     *
     * @param context - ExecutionContext for the current request
     * @returns true when token is valid (allows the request), otherwise throws UnauthorizedException
     * @throws UnauthorizedException when header/token is missing or verification fails
     */
    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const authorization = request.headers.authorization;

        if (!authorization) {
            throw new UnauthorizedException('Unauthorized');
        }

        const token = authorization.split(' ')[1];

        if (!token) {
            throw new UnauthorizedException('Unauthorized');
        }

        try {
            const tokenPayload = await this.jwtService.verifyAsync(token);
            request.user = {
                userId: tokenPayload.sub,
                username: tokenPayload.username
            }

            return true;
        } catch (error) {
            throw new UnauthorizedException('Unauthorized');
        }

    }
}
