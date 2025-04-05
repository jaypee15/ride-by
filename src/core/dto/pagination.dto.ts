import { IsArray } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

import { PaginationMetadataDto } from './page-meta.dto';
import { PaginationDto } from './page-options.dto';

export class PaginationResultDto<T> {
  @ApiProperty({
    isArray: true,
    description: 'List of items',
  })
  @IsArray()
  readonly data: T[];

  @ApiProperty({
    type: PaginationMetadataDto,
    description: 'Pagination metadata',
  })
  readonly meta: PaginationMetadataDto;

  constructor(
    data: T[],
    itemCount: number,
    options: {
      page: number;
      limit: number;
    },
  ) {
    this.data = data;
    this.meta = new PaginationMetadataDto({
      itemCount,
      pageOptionsDto: options as PaginationDto,
    });
  }
}
