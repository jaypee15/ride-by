export enum PaymentStatus {
  PENDING = 'PENDING', // Awaiting payment initiation/completion
  PAID = 'PAID', // Payment successful
  FAILED = 'FAILED', // Payment attempt failed
  REFUNDED = 'REFUNDED', // Payment was refunded
  NOT_REQUIRED = 'NOT_REQUIRED', // For free rides or cash payment (if supported)
}
