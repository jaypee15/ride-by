import { Module } from '@nestjs/common';
import { ChatGateway } from './chat.gateway';
import { MongooseModule } from '@nestjs/mongoose';
import { Message, MessageSchema } from './schemas/message.schema';
import { AppModule } from '../app.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Message.name, schema: MessageSchema }]),
    AppModule,
  ],
  providers: [ChatGateway], // Add ChatGateway
  exports: [ChatGateway], // Export if needed
})
export class CommunicationModule {}
