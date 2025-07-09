import { Logger, UseGuards } from '@nestjs/common';
import {
  OnGatewayConnection,
  OnGatewayDisconnect,
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  WsException,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { WsGuard } from '../../core/guards/ws.guard'; // Use the WS Guard
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Message, MessageDocument } from './schemas/message.schema';
import { SendMessageDto } from './dto/send-message.dto';
import { IUser } from 'src/core/interfaces'; // Assuming IUser is defined
import mongoose from 'mongoose';

// Use a different path or port if needed, ensure it doesn't conflict with AppGateway if kept separate
// Or integrate this logic into AppGateway
@WebSocketGateway({
  cors: { origin: '*' },
  // namespace: 'chat', // Optional: use a namespace
  // path: '/api/communication/socket' // Example different path
})
@UseGuards(WsGuard) // Apply guard to the whole gateway (or individual handlers)
export class ChatGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server; // Inject the server instance
  private logger = new Logger(ChatGateway.name);

  constructor(
    @InjectModel(Message.name) private messageModel: Model<MessageDocument>,
  ) {}

  // Handle connection/disconnection if needed specifically for chat
  handleConnection(client: Socket) {
    // User is already authenticated and joined their room via AppGateway/WsGuard
    const user = client.data.user as IUser;
    if (user) {
      this.logger.log(`Chat client connected: ${client.id}, User: ${user._id}`);
    } else {
      this.logger.warn(`Chat client connected without user data: ${client.id}`);
      client.disconnect(true); // Disconnect if user data somehow missing
    }
  }

  handleDisconnect(client: Socket) {
    const user = client.data.user as IUser;
    this.logger.log(
      `Chat client disconnected: ${client.id}, User: ${user?._id || 'N/A'}`,
    );
  }

  @SubscribeMessage('sendMessage')
  async handleMessage(
    @MessageBody() data: SendMessageDto,
    @ConnectedSocket() client: Socket,
  ): Promise<{ success: boolean; message?: MessageDocument }> {
    // Acknowledge message receipt
    const sender = client.data.user as IUser;
    if (!sender) {
      throw new WsException('Authentication data missing on socket.');
    }

    this.logger.log(
      `Received 'sendMessage' from ${sender._id} to ${data.receiverId}`,
    );

    try {
      // Basic validation (DTO validation happens via pipes if configured)
      if (!data.receiverId || !data.content) {
        throw new WsException('Missing receiverId or content.');
      }
      if (sender._id.toString() === data.receiverId) {
        throw new WsException('Cannot send message to yourself.');
      }

      // Save message to DB
      const newMessage = new this.messageModel({
        sender: sender._id,
        receiver: data.receiverId,
        content: data.content,
        booking: data.bookingId || undefined, // Link booking if provided
      });
      await newMessage.save();
      this.logger.log(
        `Message from ${sender._id} to ${data.receiverId} saved with ID ${newMessage._id}`,
      );

      // Emit message to the receiver's room (using their user ID as room name)
      this.server.to(data.receiverId).emit('newMessage', newMessage.toObject()); // Send plain object
      this.logger.log(`Emitted 'newMessage' to room ${data.receiverId}`);

      // Acknowledge success back to the sender
      return {
        success: true,
        message: newMessage.toObject() as MessageDocument,
      };
    } catch (error) {
      this.logger.error(
        `Error handling 'sendMessage' from ${sender._id}: ${error.message}`,
        error.stack,
      );
      // Send error back to the sender
      client.emit(
        'exception',
        `Failed to send message: ${error.message || 'Server error'}`,
      );
      return { success: false }; // Acknowledge failure
    }
  }

  // Optional: Handle message read status
  @SubscribeMessage('markAsRead')
  async handleMarkAsRead(
    @MessageBody() data: { messageId: string }, // Expect message ID
    @ConnectedSocket() client: Socket,
  ): Promise<{ success: boolean }> {
    const currentUser = client.data.user as IUser;
    if (!currentUser) {
      throw new WsException('Authentication data missing on socket.');
    }
    if (!data.messageId || !mongoose.Types.ObjectId.isValid(data.messageId)) {
      throw new WsException('Invalid messageId provided.');
    }

    try {
      const result = await this.messageModel.updateOne(
        { _id: data.messageId, receiver: currentUser._id, readAt: null }, // Find unread message for this user
        { $set: { readAt: new Date() } },
      );
      if (result.modifiedCount > 0) {
        this.logger.log(
          `Message ${data.messageId} marked as read by user ${currentUser._id}`,
        );
        // Optional: notify sender that message was read?
        return { success: true };
      } else {
        this.logger.log(
          `Message ${data.messageId} not found, not receiver, or already read by ${currentUser._id}`,
        );
        return { success: false }; // No update happened
      }
    } catch (error) {
      this.logger.error(
        `Error marking message ${data.messageId} as read: ${error.message}`,
        error.stack,
      );
      client.emit(
        'exception',
        `Failed to mark message as read: ${error.message || 'Server error'}`,
      );
      return { success: false };
    }
  }
}
