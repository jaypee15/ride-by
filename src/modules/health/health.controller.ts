import { Controller, Get, Res } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  MongooseHealthIndicator,
} from '@nestjs/terminus';
import { Response } from 'express';

@Controller('/health-check')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private mongo: MongooseHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  async check(@Res() res: Response) {
    try {
      const healthInfo = await this.health.check([
        () => this.mongo.pingCheck('mongodb', { timeout: 3000 }),
      ]);
      return res.status(200).json({ status: 200, healthInfo });
    } catch (error) {
      return res.status(503).send(error);
    }
  }
}
