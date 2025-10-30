import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { UsersModule } from 'src/users/users.module';
import { AuthService } from './auth.service';
import { PassportAuthController } from './passport-auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

/**
 * AuthModule
 *
 * Provides authentication features:
 * - Registers JwtModule asynchronously and reads JWT_SECRET from ConfigService.
 * - Configures sign options (expiresIn) for issued tokens.
 * - Registers Passport strategies (LocalStrategy, JwtStrategy) and AuthService.
 *
 * Requirements:
 * - Ensure ConfigModule.forRoot({ isGlobal: true }) is registered in AppModule
 *   so ConfigService can load environment variables (e.g. JWT_SECRET).
 */
@Module({
  providers: [AuthService, LocalStrategy, JwtStrategy],
  controllers: [PassportAuthController],
  imports: [
    UsersModule,
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        global: true,
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1d' },
      }),
      inject: [ConfigService],
    }),
    PassportModule
  ],
})
export class AuthModule { }
