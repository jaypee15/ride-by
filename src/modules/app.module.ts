import { Module } from '@nestjs/common';
import { AuthGuard } from 'src/core/guards';
import { WsGuard } from 'src/core/guards/ws.guard';
import { AppGateway } from './app.gateway';

@Module({
  providers: [AppGateway, WsGuard, AuthGuard],
  exports: [AuthGuard],
  imports: [],
})
export class AppModule {}
