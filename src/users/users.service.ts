import { Injectable } from '@nestjs/common';
import { User } from 'src/domain/entities/user';
import { PrismaService } from 'src/prisma/prisma.service';

const users: User[] = [
    {
        userId: '1',
        username: 'John Doe',
        email: '',
        password: 'password',
    },
    {
        userId: '2',
        username: 'Jane Doe',
        password: 'password',
        email: ''
    },
];

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll(): Promise<any[]> {
        return this.prisma.user.findMany();
    }

    // async findByUsername(username: string): Promise<User | undefined> {
    //     return this.prisma.user.findUnique({
    //         where: { username },
    //     });
    // }
}
