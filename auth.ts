import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from 'zod'
import { sql } from "@vercel/postgres";
import type { User } from "./app/lib/definitions";
import bcrypt from 'bcrypt'


//add credentials for hashing user name and password (security) - using bcrpyt
//and then save it to db

//we also need to getUser from db and check if the recorded hash is same as the new hash, if yes = log in succeed
async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
        return user.rows[0];
    } catch (error) {
        console.error('Failed to fetch user: ', error);
        throw new Error('Failed to fetch user.')
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig, providers: [Credentials({
        async authorize(credentials) {
            const parsedCredentials = z.object({ email: z.string().email(), password: z.string().min(6) }).safeParse(credentials);
            console.log(parsedCredentials);

            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                const user = await getUser(email);
                console.log(user);

                if (!user) return null;
                const passwordMatch = await bcrypt.compare(password, user.password);
                if (passwordMatch) return user;
            }
            console.log('Invalid credentials');

            return null
        }
    })]
})

