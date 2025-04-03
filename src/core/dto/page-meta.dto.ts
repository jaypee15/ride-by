import { PaginationDto } from './page-options.dto';
import { ApiProperty } from '@nestjs/swagger';

export interface PageMetaDtoParameters {
  pageOptionsDto: PaginationDto;
  itemCount: number;
}

export class PaginationMetadataDto {
  @ApiProperty({
    type: Number,
    description: 'Current page number',
    example: 1
  })
  readonly page: number;

  @ApiProperty({
    type: Number,
    description: 'Number of items per page',
    example: 10
  })
  readonly limit: number;

  @ApiProperty({
    type: Number,
    description: 'Total number of items',
    example: 100
  })
  readonly itemCount: number;

  @ApiProperty({
    type: Number,
    description: 'Total number of pages',
    example: 10
  })
  readonly pageCount: number;

  @ApiProperty({
    type: Boolean,
    description: 'Whether there is a previous page',
    example: false
  })
  readonly hasPreviousPage: boolean;

  @ApiProperty({
    type: Boolean,
    description: 'Whether there is a next page',
    example: true
  })
  readonly hasNextPage: boolean;

  constructor({ pageOptionsDto, itemCount }: PageMetaDtoParameters) {
    this.page = pageOptionsDto.page;
    this.limit = pageOptionsDto.limit;
    this.itemCount = itemCount;
    this.pageCount = Math.ceil(this.itemCount / this.limit);
    this.hasPreviousPage = this.page > 1;
    this.hasNextPage = this.page < this.pageCount;
  }
}
