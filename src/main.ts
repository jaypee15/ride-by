import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as express from 'express';
import { MainModule } from './modules/main.module';
import { SecretsService } from './global/secrets/service';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './core/filters';
import { LoggerInterceptor, TransformInterceptor } from './core/interceptors';
import { MongooseModule } from '@nestjs/mongoose';
import { RedisIoAdapter } from './core/adpater';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(MainModule, {
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

  // transform: true is load-bearing: DTOs rely on @Type(() => Number) to
  // coerce query strings and on property initializers for defaults
  // (e.g. maxDistance). Without it, numbers arrive as strings/undefined
  // and Mongo rejects the geo query.
  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  app.useGlobalFilters(new HttpExceptionFilter());
  app.useGlobalInterceptors(
    new LoggerInterceptor(),
    new TransformInterceptor(),
  );

  MongooseModule.forRoot(MONGO_URI);

  app.setGlobalPrefix('api');

  // Express 5 defaults to the 'simple' query parser, which leaves bracket
  // notation (origin[lat]) as flat keys. The search endpoint binds nested
  // query DTOs, so restore extended (qs) parsing.
  app.set('query parser', 'extended');
  app.useWebSocketAdapter(new RedisIoAdapter(app));

  // Setup Swagger
  const config = new DocumentBuilder()
    .setTitle('TavEazi API')
    .setDescription('The TravEazi API documentation')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(PORT);
}
bootstrap();
