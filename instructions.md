# Nigerian Intercity Carpooling Platform: Backend (NestJS) - Current State Analysis

## 1. Project Overview

This document summarizes the current state of the NestJS backend for the Nigerian Intercity Carpooling platform. The goal of the platform is to connect private car owners (Drivers) traveling between Nigerian cities with passengers (Passengers) seeking rides along the same routes, addressing issues of cost, convenience, and safety in intercity travel.

This summary is based on the provided codebase (`repomix-output.md`) and informed by the features and requirements outlined in the initial MVP PRD and the subsequent Comprehensive Product Overview document.

**Target Audience for this Document:** LLMs and Developers needing context on the existing backend structure and components to guide further development.

## 2. Technology Stack (Backend)

*   **Framework:** NestJS (v11.x) - A progressive Node.js framework using TypeScript.
*   **Language:** TypeScript
*   **Database:** MongoDB (via Mongoose ORM)
*   **Authentication:** JWT (JSON Web Tokens), Phone number OTP (implied, infrastructure partially present), Password Hashing (bcryptjs)
*   **Session Management:** Redis (via `@nestjs-modules/ioredis` and custom `UserSessionService`)
*   **Real-time Communication:** Socket.IO with Redis Adapter (for potential future features like real-time tracking/messaging)
*   **Asynchronous Tasks:** Bull (potentially for background jobs like email sending)
*   **Email:** Nodemailer (via `@nestjs-modules/mailer`) with EJS templates.
*   **Configuration:** `@nestjs/config` (using `.env` files)
*   **API Documentation:** Swagger (`@nestjs/swagger`)
*   **Validation:** `class-validator`, `class-transformer`
*   **Linting/Formatting:** ESLint, Prettier

## 3. Core Architectural Concepts

*   **Modular Design:** The application is structured into NestJS modules (`src/modules`).
*   **Global Modules:** Common services and utilities like configuration (`SecretsModule`), token generation (`TokenHelper`), and user session management (`UserSessionModule`) are grouped in `src/global` and exposed globally.
*   **Core Abstractions:** Reusable components like Guards (`AuthGuard`), Filters (`HttpExceptionFilter`), Interceptors (`LoggerInterceptor`, `TransformInterceptor`), Decorators (`User`), Helpers (`EncryptHelper`, `ErrorHelper`), and base DTOs (Pagination) are located in `src/core`.
*   **API Structure:** Primarily follows RESTful principles, managed through Controllers and Services.
*   **Data Handling:** Uses Mongoose Schemas for MongoDB interaction and DTOs (Data Transfer Objects) for API request/response validation and shaping.
*   **Error Handling:** Centralized HTTP exception filtering (`HttpExceptionFilter`) and a utility class (`ErrorHelper`) for standardized error responses.
*   **Request/Response Handling:** Uses interceptors for logging (`LoggerInterceptor`) and standardizing response format (`TransformInterceptor`).

## 4. Directory Structure Overview
src/
├── app.module.ts # Root application module
├── main.ts # Application entry point (bootstrap)
│
├── core/ # Core framework elements (guards, filters, helpers, base DTOs, etc.)
│ ├── adpater/ # WebSocket adapters (RedisIoAdapter)
│ ├── constants/ # Application-wide constants (messages, patterns)
│ ├── decorators/ # Custom decorators (@User)
│ ├── dto/ # Base DTOs (Pagination)
│ ├── enums/ # Core enumerations (PortalType)
│ ├── filters/ # Exception filters (HttpExceptionFilter)
│ ├── guards/ # Authentication/Authorization guards (AuthGuard)
│ ├── helpers/ # Utility helpers (Encryption, Error Handling)
│ ├── interceptors/ # Request/Response interceptors (Logging, Transformation)
│ ├── interfaces/ # TypeScript interfaces (User, HTTP, Roles)
│ ├── redis/ # Redis module configuration helper
│ └── validators/ # Custom class-validators
│
├── global/ # Globally available modules and services
│ ├── secrets/ # Configuration service (SecretsService)
│ ├── user-session/ # Redis-based user session management
│ ├── utils/ # Utility classes (TokenHelper)
│ └── global.module.ts # Module consolidating global providers
│
└── modules/ # Feature-specific modules
├── auth/ # Authentication, User Registration, Login, Password Mgmt
├── config/ # (Placeholder) Configuration module?
├── database/ # (Placeholder) Database configuration module?
├── driver/ # (Placeholder) Driver-specific logic
├── geolocation/ # (Placeholder) Geolocation-related logic
├── health/ # Health check endpoint (/health-check)
├── mail/ # Email sending functionality (Mailer, Templates, Events)
├── rides/ # (Placeholder) Ride management logic
└── users/ # (Placeholder) User management logic (potentially merged with Auth)


## 5. Module Breakdown & Functionality

*   **`AppModule` (`app.module.ts`):**
    *   The root module, importing necessary configuration (`ConfigModule`, `SecretsModule`), database connection (`MongooseModule`), and feature modules.
*   **`GlobalModule` (`global/global.module.ts`):**
    *   Provides `SecretsService`, `TokenHelper`, and `UserSessionService` globally.
*   **`AuthModule` (`modules/auth/`):**
    *   **Purpose:** Handles user identity, authentication, and core profile actions.
    *   **Components:**
        *   `AuthController`: Exposes endpoints for registration (`/create-user`), login (`/login`), email verification (`/confirmation`, `/resend-verification`), password reset (`/forgot-password`, `/reset-password`), logout (`/logout`), fetching user info (`/user`), changing password (`/change-password`), avatar upload (`/user/upload-avatar`), role fetching (`/roles`, `/users`).
        *   `AuthService`: Contains the business logic for user creation, validation, login, token generation, session management, password handling, email verification flows, avatar upload coordination (mentions `AwsS3Service` - integration needed).
        *   `DTOs`: Defines data structures for requests (e.g., `AuthDto`, `LoginDto`, `UpdateUserDto`, `ForgotPasswordDto`).
        *   **Entities/Schemas Used:** `User`, `Token`, `Role`.
    *   **Key Features Implemented:** Email/Password registration & login, JWT generation & verification, Redis session management, Email confirmation flow, Forgot/Reset password flow, Logout, Basic user profile fetch/update, Avatar upload (logic points to AWS S3, but service implementation not shown), Role fetching.
    *   **PRD Alignment:** Covers core Authentication and Profile Management requirements. Handles different `PortalType` (DRIVER, PASSENGER, ADMIN).
*   **`UserSessionModule` (`global/user-session/`):**
    *   **Purpose:** Manages user sessions using Redis.
    *   **Components:** `UserSessionService` provides methods to create, get, check, and delete user sessions based on user ID and a unique `sessionId` stored within the JWT. Supports "remember me" functionality.
    *   **PRD Alignment:** Crucial for maintaining user login state and security.
*   **`MailModule` (`modules/mail/`):**
    *   **Purpose:** Handles sending emails for various events.
    *   **Components:**
        *   `MailController`: Internal controller likely triggered by events or queues.
        *   `MailService`: Uses `@nestjs-modules/mailer` to send emails using EJS templates (`confirmation.ejs`, `resetpassword.ejs`, etc.).
        *   `MailEvent`: Service to trigger specific email sends (e.g., `sendUserConfirmation`, `sendResetPassword`).
        *   `EmailProcessor`: (Implied by filename `email.processor.ts`) Likely a Bull queue processor for handling email jobs asynchronously.
        *   `EmailSchema`: Mongoose schema potentially for logging email events/statuses.
        *   `Templates`: EJS files for email content.
    *   **PRD Alignment:** Fulfills requirements for sending verification and notification emails. Integration with Bull suggests asynchronous handling.
*   **`HealthModule` (`modules/health/`):**
    *   **Purpose:** Provides an endpoint (`/health-check`) to monitor application health.
    *   **Components:** `HealthController` uses `@nestjs/terminus` to check the status of dependencies (currently MongoDB).
    *   **PRD Alignment:** Good practice for monitoring and deployment.
*   **`SecretsModule` (`global/secrets/`):**
    *   **Purpose:** Loads and provides access to environment variables and configuration.
    *   **Components:** `SecretsService` extends `ConfigService` to provide typed access to secrets (DB credentials, JWT secret, Mail credentials, Redis config).
    *   **PRD Alignment:** Essential for secure configuration management.
*   **Placeholder Modules:**
    *   `RidesModule`, `RidersModule` (Driver), `GeolocationModule`, `UsersModule`, `ConfigModule`, `DatabaseModule`: These exist as empty module files (`@Module({})`). They represent planned areas of functionality that are **not yet implemented**.
    *   **PRD Alignment:** These correspond directly to core features (Ride Management, Driver specifics, Geolocation, Payments) outlined in the PRDs but require significant development.

## 6. Core Utilities & Shared Components (`src/core/`)

*   **`AuthGuard`:** Middleware to protect routes, verifying JWTs using `TokenHelper` and checking Redis sessions via `UserSessionService`.
*   **`HttpExceptionFilter`:** Catches HTTP exceptions and standardizes the error response format (`{ success: false, statusCode, message }`).
*   **`LoggerInterceptor` & `TransformInterceptor`:** Logs incoming requests and formats successful responses consistently (`{ success: true, data, message, meta? }`). Handles pagination responses specifically.
*   **`EncryptHelper`:** Wrapper around `bcryptjs` for hashing and comparing passwords.
*   **`ErrorHelper`:** Utility class to throw standardized `HttpException` types (BadRequest, Unauthorized, NotFound, etc.).
*   **`TokenHelper` (`global/utils/`):** Generates and verifies JWTs (access tokens, potentially refresh tokens, password reset tokens). Generates random strings/numbers (useful for OTPs, session IDs).
*   **Base DTOs:** `PaginationDto`, `PaginationResultDto`, `PaginationMetadataDto` provide a standard way to handle paginated API responses.
*   **`RedisIoAdapter`:** Custom Socket.IO adapter using Redis for potential multi-instance scaling of real-time features.

## 7. Database Schema (Mongoose Models Identified)

*   **`User` (`modules/auth/entities/schemas/user.schema.ts` - *Inferred Path*):**
    *   Fields: `firstName`, `lastName`, `email`, `password`, `avatar`, `about`, `country`, `gender`, `phoneNumber`, `emailConfirm`, `status`, `strategy` (Local, Google etc.), `portalType`, `roles` (Ref to Role), `lastSeen`, `createdAt`, `hasChangedPassword`.
    *   *PRD Alignment:* Covers User Data requirements for both Drivers and Passengers, including verification status and basic profile info. Needs extension for Driver-specific vehicle details.
*   **`Token` (`modules/user/schemas/token.entity.ts`):**
    *   Fields: `user` (Ref to User), `code` (likely for OTP/verification), `expiresAt`.
    *   *PRD Alignment:* Supports OTP-based verification flows (Email confirmation, Password reset).
*   **`Role` (`modules/admin/entities/role.entity.ts` - *Inferred Path*):**
    *   Fields: `name` (Enum: ADMIN, DRIVER, PASSENGER), `description`, `actions` (Permissions).
    *   *PRD Alignment:* Supports role-based access control, differentiating user types.
*   **`Email` (`modules/mail/schema/email.schema.ts`):**
    *   Fields: `event`, `email`, `timestamp`, `message_id`, etc. (Likely for tracking email sending status/webhooks).
*   **Placeholder Schemas:** `Rider`, `Rides` are mentioned in `MailModule` imports but their definitions are not included in the provided code dump. These are critical for core functionality.
*   **`Country` (`modules/seed/schemas/country.schema.ts` - *Inferred Path*):** Seems to be related to user profile data, possibly for dropdowns or validation.

## 8. External Integrations

*   **Implemented/Partially Implemented:**
    *   **Redis:** Used for User Session caching (`UserSessionService`) and Socket.IO scaling (`RedisIoAdapter`). Configured via `SecretsService`.
    *   **MongoDB:** Primary database, connection managed by `MongooseModule` using URI from `SecretsService`.
    *   **Nodemailer:** Used for sending emails via SMTP (`MailService`). Configured via `SecretsService`.
    *   **Bull:** Queue system (likely using Redis backend) for background tasks, specifically set up for email processing (`MailModule`, `EmailProcessor`).
    *   **Swagger:** API documentation generation.
*   **Mentioned/Required but Not Fully Implemented:**
    *   **Payment Gateways (Paystack, Flutterwave):** Explicitly required by PRD for payments. **No code present.**
    *   **Mapping Services (Google Maps, etc.):** Required by PRD for route visualization, geocoding, distance calculation. **No code present.**
    *   **SMS Providers:** Required by PRD for OTP phone verification. `TokenHelper` can generate OTPs, but **no SMS sending integration code present.**
    *   **AWS S3:** Mentioned in `AuthService` for avatar uploads. **`AwsS3Service` is referenced but its implementation is missing.**

## 9. Configuration & Environment

*   Managed by `SecretsService` which reads from `.env` files.
*   Key configurations include: `PORT`, `MONGO_URI`, `JWT_SECRET`, `MAIL_*` credentials, `REDIS_*` credentials.

## 10. Testing

*   Basic E2E test setup (`test/app.e2e-spec.ts`) using `supertest`.
*   Jest configuration present (`jest.config.js`, `test/jest-e2e.json`).
*   **No unit tests** specific to services or controllers were included in the dump.

## 11. Summary & Next Steps (Backend Focus)

**Current Strengths:**

*   Solid foundation using NestJS best practices (Modules, Services, Controllers, DI).
*   Core Authentication (Register, Login, JWT, Session), User Profile basics, and Notification (Email) systems are partially implemented.
*   Robust configuration management (`SecretsService`).
*   Infrastructure for background jobs (Bull) and real-time features (Socket.IO + Redis) is present.
*   Basic error handling and response standardization are in place.
*   API documentation setup (Swagger).

**Key Areas for Immediate Development (based on PRDs and missing code):**

1.  **Ride Management Module (`RidesModule`):**
    *   Implement `Rides` schema (origin, destination, waypoints, schedule, price, seats, status). Use geospatial indexing.
    *   Develop `RidesService` and `RidesController` for:
        *   Drivers: Creating, publishing, updating, canceling rides.
        *   Passengers: Searching rides (by location, date), filtering.
        *   Geospatial queries for searching.
2.  **Booking Management:**
    *   Implement `Booking` schema (linking User, Ride, status, payment info).
    *   Develop services/endpoints for:
        *   Passengers: Requesting/Booking rides, viewing bookings.
        *   Drivers: Viewing/Accepting/Rejecting booking requests.
3.  **Payment Integration (`PaymentModule`):**
    *   Integrate with Nigerian payment gateways (Paystack/Flutterwave).
    *   Implement services for:
        *   Fare calculation.
        *   Initiating payments upon booking confirmation.
        *   Handling payment callbacks/webhooks.
        *   Recording transactions.
        *   Handling payouts/refunds (longer term).
4.  **Driver Specifics (`DriverModule` / extend `AuthModule`):**
    *   Add Vehicle information to the `User` schema or a separate `Vehicle` schema (make, model, year, plate number, documents).
    *   Implement endpoints/services for driver vehicle registration and document upload (using the planned `AwsS3Service`).
    *   Implement driver verification logic.
5.  **Geolocation Module (`GeolocationModule`):**
    *   Integrate with a Mapping Service API.
    *   Implement services for:
        *   Geocoding (address to coordinates).
        *   Reverse Geocoding (coordinates to address).
        *   Route calculation (distance, estimated duration).
        *   Real-time location tracking (requires WebSocket integration).
6.  **Safety Features:**
    *   Implement backend logic for Trip Sharing (generating shareable links/tokens).
    *   Add Emergency Contact fields to `User` schema and endpoints to manage them.
    *   Implement Rating/Review system (schemas and services for Users to rate each other post-ride).
7.  **Communication:**
    *   Implement backend logic for in-app messaging (potentially using WebSockets/Redis pub-sub). Store messages.
    *   Integrate Push Notification service (e.g., FCM, APNS) for real-time updates.
    *   Integrate SMS Provider for phone number OTP verification.
8.  **Refine Existing Modules:**
    *   Add comprehensive validation (DTOs).
    *   Implement role-based authorization checks more granularly where needed.
    *   Develop Unit and Integration tests.
    *   Complete `AwsS3Service` implementation.

This document provides a snapshot of the backend's current state. Development should prioritize building out the placeholder modules (`Rides`, `Driver`, `Geolocation`, `Payment`) and integrating the required third-party services to meet the core functionality outlined in the PRDs.