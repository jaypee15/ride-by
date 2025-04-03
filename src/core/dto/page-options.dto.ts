import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, Min } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum Order {
  ASC = 'ASC',
  DESC = 'DESC',
}
export class PaginationDto {
  @ApiProperty({
    enum: Order,
    default: Order.DESC,
    required: false,
    description: 'Order direction (ASC or DESC)'
  })
  @IsEnum(Order)
  @IsOptional()
  readonly order?: Order = Order.DESC;

  @ApiProperty({
    type: Number,
    default: 1,
    required: false,
    description: 'Page number (starts from 1)'
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly page: number = 1;

  @ApiProperty({
    type: Number,
    default: 10,
    required: false,
    description: 'Number of items per page'
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @IsOptional()
  readonly limit: number = 10;

  get skip(): number {
    return (this.page - 1) * this.limit;
  }
}
