import { Logger } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { WsGuard } from 'src/core/guards';
import { ErrorHelper } from 'src/core/helpers';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  path: '/api/chat/socket',
})
export class AppGateway implements OnGatewayConnection, OnGatewayDisconnect {
  constructor(private wsGuard: WsGuard) {}

  private logger = new Logger('WebsocketGateway');

  @WebSocketServer()
  server: Server;

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  async handleConnection(client: Socket) {
    try {
      this.logger.log(`Client handleConnection: ${client.id}`);

      const user = await this.wsGuard.verifyAccessToken(
        client.handshake.auth.token || client.handshake.headers.authorization,
      );

      if (!user) {
        ErrorHelper.UnauthorizedException('User is not authorized');
      }

      client.data.user = user;

      client.join(user._id.toString());

      this.logger.log(`Client connected: ${client.id}`);
    } catch (error) {
      this.logger.log(`has issues: ${client.id}`);
      client.emit('exception', error.message);
      client.disconnect();
    }
  }
}
