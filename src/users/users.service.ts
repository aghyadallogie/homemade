import { Injectable } from '@nestjs/common';
import { User } from 'src/domain/entities/user';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(): Promise<User[]> {
        return this.prisma.user.findMany();
    }

    async findByUsername(username: string): Promise<User | null> {
        return this.prisma.user.findFirst({
            where: { username },
        });
    }

    async findByEmail(email: string): Promise<User | null> {
        return this.prisma.user.findFirst({
            where: { email },
        });
    }

    async create(data: { email: string; username: string; password: string }): Promise<User> {
        return this.prisma.user.create({ data });
    }
}
