// import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { pusherServer } from "@/app/libs/pusher";
import { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth";

import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { AuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import prisma from "@/app/libs/prismadb";

export default async function handler(
  request: NextApiRequest,
  response: NextApiResponse
) {
  const authOptions: AuthOptions = {
    adapter: PrismaAdapter(prisma),
    providers: [
      GithubProvider({
        clientId: process.env.GITHUB_CLIENT_ID as string,
        clientSecret: process.env.GITHUB_CLIENT_SECRET as string,
      }),
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID as string,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      }),
      CredentialsProvider({
        name: "credentials",
        credentials: {
          email: { label: "email", type: "text" },
          password: { label: "password", type: "password" },
        },
        async authorize(credentials) {
          if (!credentials?.email || !credentials?.password) {
            throw new Error("Invalid credentials");
          }

          const user = await prisma.user.findUnique({
            where: {
              email: credentials.email,
            },
          });

          if (!user || !user?.hashedPassword) {
            throw new Error("Invalid credentials");
          }

          const isCorrectPassword = await bcrypt.compare(
            credentials.password,
            user.hashedPassword
          );
          if (!isCorrectPassword) {
            throw new Error("Invalid credentials");
          }
          return user;
        },
      }),
    ],
    debug: process.env.NODE_ENV === "development",
    session: {
      strategy: "jwt",
    },
    secret: process.env.NEXTAUTH_SECRET,
  };

  const session = await getServerSession(request, response, authOptions);

  if (!session?.user?.email) {
    return response.status(401);
  }

  const socketId = request.body.socket_id;
  const channel = request.body.channel_name;
  const data = {
    user_id: session.user.email,
  };

  const authResponse = pusherServer.authorizeChannel(socketId, channel, data);

  return response.send(authResponse);
}
