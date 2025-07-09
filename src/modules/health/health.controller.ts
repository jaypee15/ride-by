import { Controller, Get, Res } from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  MongooseHealthIndicator,
} from '@nestjs/terminus';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Health')
@Controller('/health-check')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private mongo: MongooseHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Check API health status' })
  @ApiResponse({
    status: 200,
    description: 'API is healthy',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'number', example: 200 },
        healthInfo: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'ok' },
            info: { type: 'object' },
            error: { type: 'object' },
            details: { type: 'object' },
          },
        },
      },
    },
  })
  @ApiResponse({ status: 503, description: 'API is not healthy' })
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
