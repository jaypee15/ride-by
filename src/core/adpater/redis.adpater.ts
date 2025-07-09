import { INestApplication } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { createClient } from 'redis';
import { Server, ServerOptions } from 'socket.io';
import { SecretsService } from 'src/global/secrets/service';

export class RedisIoAdapter extends IoAdapter {
  protected redisAdapter;

  constructor(app: INestApplication) {
    super();
    const configService = app.get(SecretsService);

    const pubClient = createClient({
      socket: {
        host: configService.userSessionRedis.REDIS_HOST,
        port: parseInt(configService.userSessionRedis.REDIS_PORT, 10),
      },
      username: configService.userSessionRedis.REDIS_USER,
      password: configService.userSessionRedis.REDIS_PASSWORD,
    });
    const subClient = pubClient.duplicate();

    pubClient.connect();
    subClient.connect();

    this.redisAdapter = createAdapter(pubClient, subClient);
  }

  createIOServer(port: number, options?: ServerOptions) {
    const server = super.createIOServer(port, options) as Server;

    server.adapter(this.redisAdapter);

    return server;
  }

  bindClientConnect(server: any, callback: (socket: any) => void): void {
    server.on('connection', (socket: any) => callback(socket));
  }
}
