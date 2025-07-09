export enum RideStatus {
  SCHEDULED = 'SCHEDULED', // Ride is planned but not started
  IN_PROGRESS = 'IN_PROGRESS', // Ride has started
  COMPLETED = 'COMPLETED', // Ride finished successfully
  CANCELLED = 'CANCELLED', // Ride was cancelled (by driver or system)
}
