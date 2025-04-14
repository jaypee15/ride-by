import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';
import { Socket } from 'socket.io';

import { AuthGuard } from './authenticate.guard';

@Injectable()
export class WsGuard implements CanActivate {
  constructor(private authGuard: AuthGuard) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient();

    const authorization =
      client.handshake.auth.token || client.handshake.headers.authorization;

    if (!authorization) {
      throw new WsException('Authorization header is missing');
    }

    try {
      const user = await this.verifyAccessToken(authorization);

      client.data.user = user;

      return true;
    } catch (error) {
      throw new WsException(error.message);
    }
  }

  async verifyAccessToken(authorization: string) {
    return this.authGuard.verifyAccessToken(authorization);
  }
}
