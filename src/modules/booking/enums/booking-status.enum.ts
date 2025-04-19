export enum BookingStatus {
  PENDING = 'PENDING', // Passenger requested, driver action needed
  CONFIRMED = 'CONFIRMED', // Driver accepted, awaiting payment/start
  CANCELLED_BY_PASSENGER = 'CANCELLED_BY_PASSENGER',
  CANCELLED_BY_DRIVER = 'CANCELLED_BY_DRIVER',
  COMPLETED = 'COMPLETED', // Ride finished for this booking
  REJECTED = 'REJECTED', // Driver declined the request
  NO_SHOW = 'NO_SHOW', // Passenger didn't show up (optional)
}
