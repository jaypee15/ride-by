import { NestFactory } from '@nestjs/core';
import * as express from 'express';
import { AppModule } from './app.module';
import { SecretsService } from './global/secrets/service';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './core/filters';
import { LoggerInterceptor, TransformInterceptor } from './core/interceptors';
import { MongooseModule } from '@nestjs/mongoose';
import { RedisIoAdapter } from './core/adpater';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
    cors: true,
  });

  const { PORT, MONGO_URI } = app.get<SecretsService>(SecretsService);

  app.use(cookieParser());
  app.use(
    (
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ): void => {
      if (req.originalUrl.includes('/webhook')) {
        express.raw({ type: 'application/json' })(req, res, next);
      } else {
        express.json()(req, res, next);
      }
    },
  );

  app.useGlobalPipes(new ValidationPipe());
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(
    new LoggerInterceptor(),
    new TransformInterceptor(),
  );

  MongooseModule.forRoot(MONGO_URI);

  app.setGlobalPrefix('api');
  app.useWebSocketAdapter(new RedisIoAdapter(app));

  // Setup Swagger
  const config = new DocumentBuilder()
    .setTitle('Ride-By API')
    .setDescription('The Ride-By API documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(PORT);
}
bootstrap();
